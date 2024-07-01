package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path"
	"strings"
)

const (
	SpamLabel   = "SPAM"
	DDSpamLabel = "Malicious"
	Mwstore     = "/home/mkalappattil/malware_store"
)

func decodeEvent(body io.ReadCloser) EventObj {
	var event = EventObj{}
	// unmarshal the event object
	defer body.Close()
	b, err := io.ReadAll(body)
	if err != nil {
		log.Fatalln(err)
	}
	err = json.Unmarshal(b, &event)
	if err != nil {
		log.Fatalln(err)
	}
	return event
}

func GmailFetch(event EventObj) GmailResp {
	var gmailResp = GmailResp{}

	ctx := context.Background()
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		fmt.Sprintf(
			"https://gmail.googleapis.com/gmail/v1/users/mahesh@thedreamslab.net/messages/%s",
			event.GmailObj.MessageId),
		nil)
	if err != nil {
		log.Fatalln(err)
	}

	req.Header.Set("Authorization", "Bearer "+event.AuthEvObj.UserOauthToken)
	req.Header.Set("X-Goog-Gmail-Access-Token", event.GmailObj.AccessToken)
	client := http.DefaultClient
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}

	defer resp.Body.Close()
	contents, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}
	err = json.Unmarshal(contents, &gmailResp)
	if err != nil {
		log.Fatalln(err)
	}
	return gmailResp
}

func GmailGetDDSpamLabel(event EventObj) ([]string, error) {
	type _label_ struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Type string `json:"type"`
	}
	type _label_resp_ struct {
		Labels []_label_ `json:"labels"`
	}
	var label_resp _label_resp_

	ctx := context.Background()
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		"https://gmail.googleapis.com/gmail/v1/users/mahesh@thedreamslab.net/labels",
		nil)
	if err != nil {
		return []string{}, err
	}

	req.Header.Set("Authorization", "Bearer "+event.AuthEvObj.UserOauthToken)
	req.Header.Set("X-Goog-Gmail-Access-Token", event.GmailObj.AccessToken)
	client := http.DefaultClient
	resp, err := client.Do(req)
	if err != nil {
		return []string{}, err
	}

	defer resp.Body.Close()
	contents, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return []string{}, err
	}
	err = json.Unmarshal(contents, &label_resp)
	if err != nil {
		return []string{}, err
	}
	labels := []string{}
	for _, v := range label_resp.Labels {
		if v.Name == SpamLabel || v.Name == DDSpamLabel {
			labels = append(labels, v.ID)
		}
	}
	return labels, nil
}

func GmailLabelSpam(event EventObj, labelIDs []string) (int, error) {
	ids := ""
	for _, v := range labelIDs {
		id := fmt.Sprintf(`"%s"`, v)
		if ids == "" {
			ids = id
		} else {
			ids = ids + "," + id
		}
	}
	body := []byte(fmt.Sprintf(`{addLabelIds:[%s]}`, ids))
	//log.Printf("body:%s", bytes.NewBuffer(body))
	ctx := context.Background()
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		fmt.Sprintf(
			"https://gmail.googleapis.com/gmail/v1/users/mahesh@thedreamslab.net/messages/%s/modify?alt=json",
			event.GmailObj.MessageId),
		bytes.NewBuffer(body))
	//log.Printf("req:%+v", req)

	if err != nil {
		return http.StatusInternalServerError, err
	}

	req.Header.Set("Authorization", "Bearer "+event.AuthEvObj.UserOauthToken)
	req.Header.Set("X-Goog-Gmail-Access-Token", event.GmailObj.AccessToken)
	req.Header.Set("Content-Type", " application/json")
	client := http.DefaultClient
	resp, err := client.Do(req)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	defer resp.Body.Close()
	io.ReadAll(resp.Body)
	//log.Printf("resp:%+v", string(out))
	if err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusOK, nil
}

func fetchGmailAttachment(event EventObj, attachmentID string) (string, error) {
	type _attachment_resp_ struct {
		AttachmentID string `json:"attachmentId"`
		Size         int    `json:"size"`
		Data         string `json:"data"`
	}
	attachmentResp := _attachment_resp_{}
	ctx := context.Background()
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		fmt.Sprintf(
			"https://gmail.googleapis.com/gmail/v1/users/mahesh@thedreamslab.net/messages/%s/attachments/%s",
			event.GmailObj.MessageId, attachmentID),
		nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", "Bearer "+event.AuthEvObj.UserOauthToken)
	req.Header.Set("X-Goog-Gmail-Access-Token", event.GmailObj.AccessToken)
	client := http.DefaultClient
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()
	contents, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	err = json.Unmarshal(contents, &attachmentResp)
	if err != nil {
		return "", err
	}
	//log.Printf("fetched attachment size:%d", attachmentResp.Size)
	return attachmentResp.Data, nil
}

func analyzeContent(event EventObj, part PartObj) (sp bool, e error) {
	var (
		isSpam bool
		err    error
	)

	defer func() {
		//log.Printf("sp:%+v e:%+v", sp, e)
	}()
	// analyze urls
	emailBody, _ := base64.URLEncoding.DecodeString(part.Body.Data)
	domains, err := parseDomains(emailBody)
	if err != nil {
		return false, fmt.Errorf("[fetchURLs] err:%+v", err)
	}
	if isMaliciousDomain(domains) {
		isSpam = true
	}

	//download and analyze attachments
	b64data, err := fetchGmailAttachment(event, part.Body.AttachmentId)
	if err != nil {
		return isSpam, fmt.Errorf("[downloadAttachment] err:%+v", err)
	}
	data, err := base64.URLEncoding.DecodeString(b64data)
	fileName := "noname"
	for _, header := range part.Headers {
		s := strings.Split(header.Value, "filename=")
		if len(s) > 1 {
			fileName = strings.ReplaceAll(s[1], `"`, ``)
			break
		}
	}

	filePath := path.Join(Mwstore, fileName)
	f, err := os.Create(filePath)
	if err != nil {
		return false, fmt.Errorf("[downloadAttachment] err:%+v", err)
	}
	f.Write(data)
	f.Close()
	cmd := exec.Command("md5sum", filePath)
	md5, err := cmd.Output()
	if err != nil {
		os.RemoveAll(filePath)
		return false, fmt.Errorf("[downloadAttachment] err:%+v", err)
	}
	analysisURL, err := uploadFileVT(filePath)
	if err != nil {
		os.RemoveAll(filePath)
		return false, fmt.Errorf("[downloadAttachment] err:%+v", err)
	}

	isMalicious, err := getAnalysisResultsVT(analysisURL)
	os.RemoveAll(filePath)
	if err != nil {
		return false, fmt.Errorf("[downloadAttachment] err:%+v", err)
	}

	if !isMalicious {
		return isSpam, nil
	}

	isSpam = false // right now using the tool for analyzing attachments

	f, _ = os.Create(filePath + ".md5")
	f.Write(md5)
	f.Close()
	//now compress the file
	archiveFilePath := filePath + ".zip"
	archive, err := os.Create(archiveFilePath)
	if err != nil {
		return false, fmt.Errorf("[downloadAttachment] err:%+v", err)
	}
	defer archive.Close()
	zipWriter := zip.NewWriter(archive)
	w2, err := zipWriter.Create(fileName)
	if err != nil {
		return false, fmt.Errorf("[downloadAttachment] err:%+v", err)
	}
	if _, err := io.Copy(w2, bytes.NewReader(data)); err != nil {
		return false, fmt.Errorf("[downloadAttachment] err:%+v", err)
	}
	zipWriter.Close()
	return isSpam, err
}
