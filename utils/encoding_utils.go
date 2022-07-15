package utils

import (
	"encoding/base64"
)

func Base64UrlEncode(data []byte) string {
	rawURLEncoding := base64.RawURLEncoding
	return rawURLEncoding.EncodeToString(data)
}

func Base64UrlDecode(data string) []byte {
	rawURLEncoding := base64.RawURLEncoding
	decodedDataBytes, _ := rawURLEncoding.DecodeString(data)
	return decodedDataBytes
}
