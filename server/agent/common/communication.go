package common

// Alert represents an alert to be sent to the server
type Alert struct {
	Source      string      `json:"source"`
	AlertType   string      `json:"alert_type"`
	Description string      `json:"description"`
	Data        interface{} `json:"data"`
}