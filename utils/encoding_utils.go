package utils

import (
	"encoding/base64"
	"encoding/hex"
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

func HexUrlEncode(data []byte) string {
	return hex.EncodeToString(data)
}

func HexUrlDecode(data string) []byte {
	decodedDataBytes, _ := hex.DecodeString(data)
	return decodedDataBytes
}

func EncodeData(data []byte, encodingType string) string {
	if encodingType == "BASE64" {
		return Base64UrlEncode(data)
	} else {
		return HexUrlEncode(data)
	}
}

func DecodeData(data string, encodingType string) []byte {
	if encodingType == "BASE64" {
		return Base64UrlDecode(data)
	} else {
		return HexUrlDecode(data)
	}
}
