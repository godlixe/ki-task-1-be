package helper

type Response struct {
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}
