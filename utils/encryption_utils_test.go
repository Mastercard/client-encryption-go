package utils_test

import (
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
