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
