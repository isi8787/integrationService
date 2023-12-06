package gateways

import (
	"io"
	"net/http"
	"net/url"

	log "github.com/sirupsen/logrus"
)

// HTTP Method Constants
const (
	// MethodGet HTTP method
	MethodGet = "GET"

	// MethodPost HTTP method
	MethodPost = "POST"

	// MethodPut HTTP method
	MethodPut = "PUT"

	// MethodDelete HTTP method
	MethodDelete = "DELETE"

	// MethodPatch HTTP method
	MethodPatch = "PATCH"

	// MethodHead HTTP method
	MethodHead = "HEAD"

	// MethodOptions HTTP method
	MethodOptions = "OPTIONS"
)

// HTTP Status Codes
const (
	SuccessCode          = 200
	AcceptedCode         = 201
	UnAuthorized         = 401
	JsonMarshalErrorCode = 4000
	IoReadErrorCode      = 4001
	ConfigErrorCode      = 4002
	ConversionErrorCode  = 4003
	UrlParamErrorCode    = 4004
)

// Application Error Messages
const (
	UnAuthorizedMessage           = "Unauthorized."
	ConfigErrorMessage            = "Configuration Error."
	ConversionErrorMessage        = "Conversion Error."
	UrlParamNotExistsErrorMessage = "URL Param Not Exists."
	FailedToConnectRedis          = "Failed to connect Redis DB."
)

type RequestParams struct {
	Method      string
	Url         string
	Body        io.Reader
	QueryParams url.Values
}

type ApiError struct {
	Status bool         `json:"status"`
	Err    ErrorDetails `json:"error"`
}

type ErrorDetails struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

type ApiSuccess struct {
	Status bool        `json:"status"`
	Result interface{} `json:"result"`
}

// to perform http request by request params
func HttpRequest(req *http.Request, opts *RequestParams) (*http.Response, error) {
	// @TODO: TLS enablement: Need to use IAM module with TLS once it is ready.
	client := &http.Client{}
	req.Header.Add("Content-Type", "application/json")
	if opts.QueryParams != nil {
		req.URL.RawQuery = opts.QueryParams.Encode()
	}
	log.Info("#### REQUEST DETAILS START ####")
	log.Info(req)
	log.Info("#### REQUEST DETAILS END ####")
	return client.Do(req)
}
