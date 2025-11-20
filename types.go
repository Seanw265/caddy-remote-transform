package caddydynamictransform

// Data structures for JSON serialization

// TransformRequest represents the request payload sent to the transform endpoint.
type TransformRequest struct {
	Request RequestData `json:"request"`
	Meta    MetaData    `json:"meta"`
}

// RequestData contains the serialized HTTP request data.
type RequestData struct {
	URL     string              `json:"url"`
	Headers map[string][]string `json:"headers"`
	Body    BodyData            `json:"body"`
}

// BodyData represents the request/response body with its encoding.
type BodyData struct {
	Encoding string `json:"encoding"`
	Value    string `json:"value"`
}

// MetaData contains metadata about the request.
type MetaData struct {
	RequestID  string `json:"requestId,omitempty"`
	Timestamp  string `json:"timestamp"`
	ClientIP   string `json:"clientIp"`
	ServerName string `json:"serverName"`
}

// TransformResponse represents the response from the transform endpoint.
type TransformResponse struct {
	Request  *RequestData  `json:"request"`
	Response *ResponseData `json:"response,omitempty"`
}

// ResponseData contains the response to return to the client.
type ResponseData struct {
	Status  int                `json:"status"`
	Headers map[string][]string `json:"headers"`
	Body    BodyData           `json:"body"`
}

