package jwe

import (
	"encoding/json"

	"github.com/mastercard/client-encryption-go/utils"
)

type JOSEHeader struct {
	Alg string `json:"alg"`
	Enc string `json:"enc"`
	Kid string `json:"kid"`
	Cty string `json:"cty"`
}

func (header JOSEHeader) ToJson() ([]byte, error) {
	jsonHeader, err := json.Marshal(header)
	if err != nil {
		return nil, err
	}
	return jsonHeader, nil
}

func ParseJOSEHeader(encodedHeader string) (*JOSEHeader, error) {
	decodedHeader := utils.Base64UrlDecode(encodedHeader)
	var joseHeader JOSEHeader
	err := json.Unmarshal(decodedHeader, &joseHeader)
	if err != nil {
		return nil, err
	}
	return &joseHeader, nil
}
