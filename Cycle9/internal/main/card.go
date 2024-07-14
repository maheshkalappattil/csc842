package main

type T struct {
	Action struct {
		Notification struct {
			Text string `json:"text"`
		} `json:"notification"`
	} `json:"action"`
	HostAppAction struct {
		GmailAction struct {
			OpenCreatedDraftAction struct {
				DraftId            string `json:"draftId"`
				ThreadServerPermId string `json:"threadServerPermId"`
			} `json:"openCreatedDraftAction"`
		} `json:"gmailAction"`
	} `json:"hostAppAction"`
}
