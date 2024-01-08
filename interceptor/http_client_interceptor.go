// Package interceptor handles oauth signing of every http request before
// sending.
package interceptor

import (
	"bytes"
	"github.com/Duong2903/client-encryption-go/encryption"
	"github.com/Duong2903/client-encryption-go/jwe"
	"github.com/Duong2903/client-encryption-go/utils"
	"io"
	"net/http"
)

// The httpClientInterceptor is the composition of http.RoundTripper and jwe.JWEConfig
// Every http call can be intercepted through http.RoundTripper
// jwe.JWEConfig is used to instruct the encryption library how requests should be encrypted/decrypted
// The sign function is used to sign the request using OAuth 1.0a
type httpClientInterceptor struct {
	http.RoundTripper
	jwe.JWEConfig
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
	encryptedPayload := encryption.EncryptPayload(reqBody, h.JWEConfig)

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
	decryptedPayload := encryption.DecryptPayload(encryptedPayload, h.JWEConfig)
	resp.Body = io.NopCloser(bytes.NewReader([]byte(decryptedPayload)))
	return resp
}

// GetHttpClient provides the http.Client having capability to intercept
// the http call and perform encryption/decryption as-well as add the
// generated oauth1.0a header in each request.
// config: used to instruct the encryption library how requests should be encrypted/decrypted
// sign: function used to sign the request using OAuth 1.0a. If OAuth isn't required, 'nil' can be used
func GetHttpClient(config jwe.JWEConfig, sign func(req *http.Request) error) (*http.Client, error) {
	return &http.Client{
		Transport: &httpClientInterceptor{
			http.DefaultTransport,
			config,
			sign,
		},
	}, nil
}
