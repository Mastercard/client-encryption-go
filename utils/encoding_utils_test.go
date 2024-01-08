package utils_test

import (
	"testing"

	"github.com/mastercard/client-encryption-go/utils"
	"github.com/stretchr/testify/assert"
)

func TestBase64UrlEncode(t *testing.T) {
	header := "{\"alg\":\"RSA-OAEP\",\"enc\":\"A256GCM\"}"
	encodedHeader := utils.Base64UrlEncode([]byte(header))
	expected := "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ"
	assert.Equal(t, expected, encodedHeader)

	data := "light work"
	encodedHeader = utils.Base64UrlEncode([]byte(data))
	expected = "bGlnaHQgd29yaw"
	assert.Equal(t, expected, encodedHeader)
}

func TestBase64UrlDecode(t *testing.T) {
	encodedHeader := "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ"
	decodedHeader := utils.Base64UrlDecode(encodedHeader)
	expected := "{\"alg\":\"RSA-OAEP\",\"enc\":\"A256GCM\"}"
	assert.Equal(t, []byte(expected), decodedHeader)
}

func TestHexUrlEncode(t *testing.T) {
	data := "light work"
	encodedData := utils.HexUrlEncode([]byte(data))
	expected := "6c6967687420776f726b"
	assert.Equal(t, expected, encodedData)
}

func TestHexUrlDecode(t *testing.T) {
	data := "6c6967687420776f726b"
	decodedData := utils.HexUrlDecode(data)
	expected := "light work"
	assert.Equal(t, expected, string(decodedData))
}

func TestEncodeDataShouldUseTheCorrectEncodingType(t *testing.T) {
	// HEX Encoding
	data := "light work"
	encodedData := utils.EncodeData([]byte(data), "HEX")
	expected := "6c6967687420776f726b"
	assert.Equal(t, expected, encodedData)

	// BASE64 Encoding
	data = "light work"
	encodedData = utils.EncodeData([]byte(data), "BASE64")
	expected = "bGlnaHQgd29yaw"
	assert.Equal(t, expected, encodedData)
}

func TestDecodeDataShouldUseTheCorrectEncodingType(t *testing.T) {
	// HEX Encoding
	data := "6c6967687420776f726b"
	decodedData := utils.DecodeData(data, "HEX")
	expected := "light work"
	assert.Equal(t, expected, string(decodedData))

	// BASE64 Encoding
	data = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ"
	decodedData = utils.Base64UrlDecode(data)
	expected = "{\"alg\":\"RSA-OAEP\",\"enc\":\"A256GCM\"}"
	assert.Equal(t, []byte(expected), decodedData)
}
