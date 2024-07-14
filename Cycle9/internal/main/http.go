package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"net/http"
)

func doHTTPGet(url string, headers map[string]string) ([]byte, error) {
	ctx := context.Background()
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		url,
		nil)
	if err != nil {
		return nil, err
	}

	for h, v := range headers {
		req.Header.Set(h, v)
	}
	client := http.DefaultClient
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func doHTTPPost(url string, body []byte, headers map[string]string) ([]byte, error) {
	var r io.Reader = nil
	var err error
	var bodyJson []byte
	if body != nil {
		bodyJson, err = json.Marshal(body)
		r = bytes.NewReader(bodyJson)
	}
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		url,
		r,
	)
	log.Printf("req:%+v", req)
	if err != nil {
		return nil, err
	}

	for h, v := range headers {
		req.Header.Set(h, v)
	}
	client := http.DefaultClient
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return b, nil
}
