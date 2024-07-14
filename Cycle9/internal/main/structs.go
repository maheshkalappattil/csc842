package main

type EventObj struct {
	CommonEvObj CommonEventObject        `json:"commonEventObject"`
	GmailObj    GmailObject              `json:"gmail"`
	AuthEvObj   AuthorizationEventObject `json:"authorizationEventObject"`
}

type CommonEventObject struct {
	HostApp  string `json:"hostApp""`
	Platform string `json:"platform"`
}

type GmailObject struct {
	MessageId   string `json:"messageId"`
	ThreadId    string `json:"threadId"`
	AccessToken string `json:"accessToken"`
}

type AuthorizationEventObject struct {
	UserOauthToken string `json:"userOauthToken""`
	userIdToken    string `json:"userIdToken"`
	SystemIdToken  string `json:"systemIdToken"`
}

type GmailResp struct {
	Payload GmailPayload `json:"payload,omitempty"`
}

type GmailPayload struct {
	PartId       string      `json:"partId"`
	MimeType     string      `json:"mimeType"`
	Filename     string      `json:"filename,omitempty"`
	Body         BodyObj     `json:"body,omitempty"`
	Headers      []HeaderObj `json:"headers,omitempty"`
	Parts        []PartObj   `json:"parts,omitempty"`
	SizeEstimate uint64      `json:"sizeEstimate"`
	InternalDate string      `json:"internalDate"`
}

type BodyObj struct {
	Size         uint64 `json:"size,omitempty"`
	Data         string `json:"data,omitempty"`
	AttachmentId string `json:"attachmentId,omitempty"`
}
type HeaderObj struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type PartObj struct {
	PartId   string      `json:"partId"`
	MimeType string      `json:"mimeType"`
	Headers  []HeaderObj `json:"headers,omitempty"`
	Body     BodyObj     `json:"body,omitempty"`
}
