// Package interceptor handles oauth signing of every http request before
// sending.
package mastercard_interceptor

import (
	"bytes"
	"github.com/mastercard/client-encryption-go/field_level_encryption"
	"github.com/mastercard/client-encryption-go/mastercard_encryption"
	"github.com/mastercard/client-encryption-go/utils"
	"io"
	"net/http"
)

// The httpClientInterceptor is the composition of http.RoundTripper and field_level_encryption.field_level_encryption_config
// Every http call can be intercepted through http.RoundTripper
// field_level_encryption.field_level_encryption_config is used to instruct the encryption library how requests should be encrypted/decrypted
// The sign function is used to sign the request using OAuth 1.0a
type httpClientInterceptor struct {
	http.RoundTripper
	field_level_encryption.FieldLevelEncryptionConfig
	sign func(req *http.Request) error
}

// RoundTrip intercepts every http call and response and performs encryption, decryption and request signing
func (h *httpClientInterceptor) RoundTrip(req *http.Request) (*http.Response, error) {
	// Modify the request before sending
	modifiedReq := h.ModifyRequest(req)

	// Sign the request using OAuth 1.0a if applicable
	if h.sign != nil {
		err := h.sign(modifiedReq)
		if err != nil {
			return nil, err
		}
	}

	// Send the request
	resp, _ := h.RoundTripper.RoundTrip(modifiedReq)

	// Modify the response
	modifiedResp := h.ModifyResponse(resp)

	return modifiedResp, nil
}

// ModifyRequest encrypts outgoing requests using JWE encryption
func (h *httpClientInterceptor) ModifyRequest(req *http.Request) *http.Request {
	reqBody := utils.ParseReader(req.Body)
	encryptedPayload := mastercard_encryption.EncryptPayload(reqBody, h.FieldLevelEncryptionConfig)

	modReqBody := []byte(encryptedPayload)
	modReqBodyLen := len(modReqBody)

	newReq, _ := http.NewRequest(req.Method, req.URL.String(), io.Reader(bytes.NewReader(modReqBody)))
	newReq.ContentLength = int64(modReqBodyLen)
	newReq.Header = req.Header

	return newReq
}

// ModifyResponse decrypts incoming responses using JWE decryption
func (h *httpClientInterceptor) ModifyResponse(resp *http.Response) *http.Response {
	encryptedPayload := utils.ParseReader(resp.Body)
	decryptedPayload := mastercard_encryption.DecryptPayload(encryptedPayload, h.FieldLevelEncryptionConfig)
	resp.Body = io.NopCloser(bytes.NewReader([]byte(decryptedPayload)))
	return resp
}

// GetHttpClient provides the http.Client having capability to intercept
// the http call and perform encryption/decryption as-well as add the
// generated oauth1.0a header in each request.
// config: used to instruct the encryption library how requests should be encrypted/decrypted
// sign: function used to sign the request using OAuth 1.0a. If OAuth isn't required, 'nil' can be used
func GetHttpClient(config field_level_encryption.FieldLevelEncryptionConfig, sign func(req *http.Request) error) (*http.Client, error) {
	return &http.Client{
		Transport: &httpClientInterceptor{
			http.DefaultTransport,
			config,
			sign,
		},
	}, nil
}
