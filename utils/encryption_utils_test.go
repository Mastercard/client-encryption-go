package utils_test

import (
	"github.com/Jeffail/gabs/v2"
	"testing"

	"github.com/mastercard/client-encryption-go/utils"
	"github.com/stretchr/testify/assert"
)

func TestLoadEncryptionCertificate_ShouldSupportPem(t *testing.T) {
	const certificatePath = "../testdata/certificates/test_certificate-2048.pem"
	_, err := utils.LoadEncryptionCertificate(certificatePath)
	assert.Nil(t, err)
}

func TestLoadEncryptionCertificate_ShouldSupportDer(t *testing.T) {
	const certificatePath = "../testdata/certificates/test_certificate-2048.der"
	_, err := utils.LoadEncryptionCertificate(certificatePath)
	assert.Nil(t, err)
}

func TestLoadDecryptionKey(t *testing.T) {
	var keyPath = "../testdata/keys/pkcs12/test_key.p12"
	_, err := utils.LoadDecryptionKey(keyPath, "Password1")
	assert.Nil(t, err)
}

func TestLoadUnencryptedDecryptionKey(t *testing.T) {
	var keyPath = "../testdata/keys/pkcs1/test_key_pkcs1-2048.pem"
	_, err := utils.LoadUnencryptedDecryptionKey(keyPath)
	assert.Nil(t, err)
}

func TestGetPayloadToEncryptWithRootPayload_ShouldReturnEntirePayload(t *testing.T) {
	jsonPath := "$"
	payload := `{"path":{"to":{"foo":{"sensitiveField1":"sensitiveValue1","sensitiveField2":"sensitiveValue2"}}}}`
	jsonPayload, _ := gabs.ParseJSON([]byte(payload))
	payloadToEncrypt := utils.GetPayloadToEncrypt(jsonPayload, jsonPath)
	assert.Equal(t, payload, payloadToEncrypt)
}

func TestGetPayloadToEncryptWithPayloadPath_ShouldReturnPayloadAtPath(t *testing.T) {
	jsonPath := "path.to.foo"
	payload := `{"path":{"to":{"foo":{"sensitiveField1":"sensitiveValue1","sensitiveField2":"sensitiveValue2"}}}}`
	jsonPayload, _ := gabs.ParseJSON([]byte(payload))
	payloadToEncrypt := utils.GetPayloadToEncrypt(jsonPayload, jsonPath)
	assert.Equal(t, `{"sensitiveField1":"sensitiveValue1","sensitiveField2":"sensitiveValue2"}`, payloadToEncrypt)
}

func TestGetPayloadToDecryptWithRootPayload_ShouldReturnEntirePayload(t *testing.T) {
	jsonPath := "$"
	payload := `{"encryptedPayload":"abcdefg"}`
	jsonPayload, _ := gabs.ParseJSON([]byte(payload))
	payloadToDecrypt := utils.GetPayloadToDecrypt(jsonPayload, jsonPath)
	assert.Equal(t, "abcdefg", payloadToDecrypt)
}

func TestGetPayloadToDecryptWithRootPayload_ShouldReturnPayloadAtPath(t *testing.T) {
	jsonPath := "path.to.encryptedFoo.encryptedData"
	payload := `{"path":{"to":{"encryptedFoo":{"encryptedData":"abcdefg"}}}}`
	jsonPayload, _ := gabs.ParseJSON([]byte(payload))
	payloadToDecrypt := utils.GetPayloadToDecrypt(jsonPayload, jsonPath)
	assert.Equal(t, "abcdefg", payloadToDecrypt)
}
