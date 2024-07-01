package main

import (
	"fmt"
	"github.com/dreamslab/dd/pkg/swagger/server/restapi"
	"github.com/dreamslab/dd/pkg/swagger/server/restapi/operations"
	"github.com/go-openapi/loads"
	"github.com/go-openapi/runtime/middleware"
	"io"
	"log"
)

func main() {

	// Initialize Swagger
	swaggerSpec, err := loads.Analyzed(restapi.SwaggerJSON, "")
	if err != nil {
		log.Fatalln(err)
	}

	api := operations.NewDdAPI(
		swaggerSpec)
	server := restapi.NewServer(api)

	defer func() {
		if err := server.Shutdown(); err != nil {
			// error handle
			log.Fatalln(err)
		}
	}()

	server.Host = "0.0.0.0"
	server.TLSPort = 5556
	server.TLSCertificate = "/etc/letsencrypt/live/thedreamslab.net/fullchain.pem"
	server.TLSCertificateKey = "/etc/letsencrypt/live/thedreamslab.net/privkey.pem"
	api.PostDdScanallHandler = operations.PostDdScanallHandlerFunc(PostDdScanall)
	api.PostDdScanoneHandler = operations.PostDdScanoneHandlerFunc(PostDdScanone)
	// Start server which listening
	if err := server.Serve(); err != nil {
		log.Fatalln(err)
	}
}

func PostDdScanall(param operations.PostDdScanallParams) middleware.Responder {
	defer param.HTTPRequest.Body.Close()
	b, err := io.ReadAll(param.HTTPRequest.Body)
	if err != nil {
		log.Fatalln(err)
	}
	log.Printf("PostDdScanall: body:%+v", string(b))
	return operations.NewPostDdScanallOK().WithPayload(fmt.Sprintf("body:%+v", string(b)))
}

func PostDdScanone(param operations.PostDdScanoneParams) middleware.Responder {
	var (
		spamYet = false
	)

	// unmarshal the event object
	event := decodeEvent(param.HTTPRequest.Body)

	// fetch the mail
	gmailResp := GmailFetch(event)
	labelIDs, err := GmailGetDDSpamLabel(event) // TODO: add caching
	if err != nil {
		log.Printf("error fetching Defender Spam Label: %s", err.Error())
	}

	//base64 decode the email body
	for _, part := range gmailResp.Payload.Parts {
		//log.Printf("part: %+v", part)
		isMalicious, err := analyzeContent(event, part)
		log.Printf("part: %s isMalicious: %+v, err:%s",
			part.PartId, isMalicious, err.Error())
		if isMalicious && !spamYet {
			log.Printf("marking as spam")
			httpStatus, err := GmailLabelSpam(event, labelIDs)
			if err != nil {
				log.Printf("http status:%d err:%s", httpStatus, err)
				continue
			}
			spamYet = true
		}
	}
	payload := &operations.PostDdScanoneOKBody{
		Action: &operations.PostDdScanoneOKBodyAction{
			Notification: &operations.PostDdScanoneOKBodyActionNotification{
				Text: "success",
			},
		},
	}
	return operations.NewPostDdScanoneOK().WithPayload(payload)
}
