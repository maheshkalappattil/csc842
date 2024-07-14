package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	//URLRegexp = `((([A-Za-z]{3,9}:(?:\/\/)?)(?:[-;:&=\+\$,\w]+@)?[A-Za-z0-9.-]+|(?:www.|[-;:&=\+\$,\w]+@)[A-Za-z0-9.-]+)((?:\/[\+~%\/.\w-_]*)?\??(?:[-\+=&;%@.\w_]*)#?(?:[.\!\/\\w]*))?)`
	URLRegexp    = `((http:\/\/)|(https:\/\/)|(www\.))([^:\/\n\s\)\;\(\"]{1,64})`
	DomainRegexp = `([^\.]*\.[^\.]+$)`
	VTAPIURL     = "https://www.virustotal.com/api/v3/domains"
	VTFileURL    = "https://www.virustotal.com/api/v3/files"
	VTAPIKEY     = "94ab0270af40bc17d4a490e72204bb41dac782c8f8b930b3c2deaddea7e0368e"
)

func parseDomains(content []byte) ([]string, error) {
	r := regexp.MustCompile(URLRegexp)
	urls := r.FindAllString(string(content), -1)

	r = regexp.MustCompile(DomainRegexp)
	var domains []string
	for _, url := range urls {
		domain := strings.ReplaceAll(r.FindString(url), "http://", "")
		domain = strings.ReplaceAll(domain, "https://", "")
		domain = strings.ReplaceAll(domain, "www.", "")
		domains = append(domains, domain)
	}
	domains = removeDuplicates(domains)
	return domains, nil
}

func removeDuplicates(a []string) []string {
	b := []string{}
	m := make(map[string]string)
	for _, v := range a {
		if _, ok := m[v]; !ok {
			m[v] = v
			b = append(b, v)
		}
	}
	return b
}

func isMaliciousDomain(domains []string) bool {
	first := true
	for _, domain := range domains {
		if first {
			first = false
		} else {
			<-time.After(16 * time.Second)
		}
		isSpamURL, err := scanURLVT(domain)
		if err == nil && isSpamURL == true {
			return true
		}
	}
	return false
}

type _scan_domain_resp_ struct {
	Data struct {
		Attributes struct {
			Categories map[string]string
			TotalVotes struct {
				Harmless  int `json:"harmless"`
				Malicious int `json:"malicious"`
			} `json:"total_votes"`
		} `json:"attributes"`
	} `json:"data"`
}

func scanURLVT(domain string) (bool, error) {
	headers := map[string]string{
		"x-apikey":     VTAPIKEY,
		"Content-Type": "application/json",
	}
	b, err := doHTTPPost(fmt.Sprintf("%s/%s", VTAPIURL, domain), nil, headers)
	if err != nil {
		return false, err
	}
	log.Printf("domainResp:%+v", string(b))
	var domainResp _scan_domain_resp_
	domainResp.Data.Attributes.Categories = make(map[string]string)
	err = json.Unmarshal(b, &domainResp)
	if err != nil {
		return false, err
	}
	harmless := float64(domainResp.Data.Attributes.TotalVotes.Harmless)
	malicious := float64(domainResp.Data.Attributes.TotalVotes.Malicious)
	percent := malicious / (malicious + harmless)
	log.Printf("harmless:%02.0f malicious:%02.0f percent:%02.2f", harmless, malicious, percent)
	if malicious/(malicious+harmless) > 0.5 {
		log.Printf("domain:%s malicious:yes", domain)
		return true, nil
	}
	for _, v := range domainResp.Data.Attributes.Categories {
		if strings.Contains(strings.ToLower(v), "malicious") {
			log.Printf("domain:%s malicious:yes", domain)
			return true, nil
		}
	}
	log.Printf("domain:%s malicious:no", domain)
	return false, nil
}

func uploadFileVT(filePath string) (string, error) {
	type _resp_ struct {
		Data struct {
			Type  string `json:"type"`
			ID    string `json:"id"`
			Links struct {
				Self string `json:"self"`
			} `json:"links"`
		} `json:"data"`
	}

	log.Printf("uploading file %s to VT", filePath)
	// open the file
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	// Pipe the file so as not to read it into memory
	bodyReader, bodyWriter := io.Pipe()
	// create a multipat/mime writer
	writer := multipart.NewWriter(bodyWriter)
	// get the Content-Type of our form data
	fdct := writer.FormDataContentType()

	// Read file errors from the channel
	errChan := make(chan error, 1)
	go func() {
		defer bodyWriter.Close()
		defer file.Close()
		part, err := writer.CreateFormFile("file", filepath.Base(filePath))
		if err != nil {
			errChan <- err
			return
		}
		if _, err := io.Copy(part, file); err != nil {
			errChan <- err
			return
		}
		errChan <- writer.Close()
	}()

	// create a HTTP request with our body, that contains our file
	postReq, err := http.NewRequest("POST", VTFileURL, bodyReader)
	if err != nil {
		return "", err
	}
	postReq.Header.Add("Content-Type", fdct)
	postReq.Header.Add("x-apikey", VTAPIKEY)
	client := http.DefaultClient

	// send our request off, get response and/or error
	resp, err := client.Do(postReq)
	if cerr := <-errChan; cerr != nil {
		return "", cerr
	}
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	log.Printf("body:%+v", string(b))
	d := _resp_{}
	err = json.Unmarshal(b, &d)
	if err != nil {
		log.Printf("failed to unmarshal:%+v", err)
		return "", err
	}
	log.Printf("d:%+v", d)
	return d.Data.Links.Self, nil
}

func getAnalysisResultsVT(analysisURL string) (bool, error) {
	type _resp_ struct {
		Meta struct {
			FileInfo struct {
				Sha256 string `json:"sha256"`
				Sha1   string `json:"sha1"`
				Md5    string `json:"md5"`
				Size   int    `json:"size"`
			} `json:"file_info"`
		} `json:"meta"`
		Data struct {
			Attributes struct {
				Date   int    `json:"date"`
				Status string `json:"status"`
				Stats  struct {
					Harmless         int `json:"harmless"`
					TypeUnsupported  int `json:"type-unsupported"`
					Suspicious       int `json:"suspicious"`
					ConfirmedTimeout int `json:"confirmed-timeout"`
					Timeout          int `json:"timeout"`
					Failure          int `json:"failure"`
					Malicious        int `json:"malicious"`
					Undetected       int `json:"undetected"`
				} `json:"stats"`
				Results struct {
				} `json:"results"`
			} `json:"attributes"`
			Type  string `json:"type"`
			Id    string `json:"id"`
			Links struct {
				Item string `json:"item"`
				Self string `json:"self"`
			} `json:"links"`
		} `json:"data"`
	}
	headers := map[string]string{
		"x-apikey":     VTAPIKEY,
		"Content-Type": "application/json",
	}
	var dataResp _resp_
	for i := 0; i < 30; i++ {
		log.Printf("waiting for 10secs for analysis to complete...")
		<-time.After(10 * time.Second)
		b, err := doHTTPGet(analysisURL, headers)
		if err != nil {
			return false, err
		}

		dataResp = _resp_{}
		err = json.Unmarshal(b, &dataResp)
		if err != nil {
			return false, err
		}
		if dataResp.Data.Attributes.Status != "queued" {
			break
		}
	}
	log.Printf("analysis Results:")
	log.Printf("================")
	log.Printf("%+v", dataResp)
	log.Printf("================")
	isMalicious := false
	if dataResp.Data.Attributes.Stats.Malicious > 0 || dataResp.Data.Attributes.Stats.Suspicious > 0 {
		isMalicious = true
	}
	return isMalicious, nil
}
