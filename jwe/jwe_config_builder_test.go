package jwe_test

import (
	"crypto/rsa"
	"testing"

	"github.com/mastercard/client-encryption-go/jwe"
	"github.com/mastercard/client-encryption-go/utils"
	"github.com/stretchr/testify/assert"
)

func TestJWEConfigBuilder(t *testing.T) {
	decryptionKeyPath := "../testdata/keys/pkcs1/test_key_pkcs1-2048.pem"
	certificatePath := "../testdata/certificates/test_certificate-2048.der"

	decryptionKey, err := utils.LoadUnencryptedDecryptionKey(decryptionKeyPath)
	assert.Nil(t, err)
	certificate, err := utils.LoadEncryptionCertificate(certificatePath)
	assert.Nil(t, err)
	cek := []byte("cek")
	iv := []byte("iv")

	configBuilder := jwe.NewJWEConfigBuilder()
	jweConfig := configBuilder.WithDecryptionKey(decryptionKey).
		WithCertificate(certificate).
		WithCek(cek).
		WithIv(iv).
		Build()

	assert.Equal(t, jweConfig.GetDecryptionKey(), decryptionKey)
	assert.Equal(t, jweConfig.GetCertificate(), certificate)
	assert.Equal(t, "encryptedData", jweConfig.GetEncryptedValueFieldName())
	assert.Equal(t, jweConfig.GetEncryptionKey(), certificate.PublicKey.(*rsa.PublicKey))
	assert.Equal(t, jweConfig.GetCek(), cek)
	assert.Equal(t, jweConfig.GetIv(), iv)

}

func TestBuild_ShouldComputeCertificateKeyFingerprint_WhenFingerprintNotSet(t *testing.T) {
	const decryptionKeyPath = "../testdata/keys/pkcs1/test_key_pkcs1-2048.pem"
	const certificatePath = "../testdata/certificates/test_certificate-2048.der"

	decryptionKey, err := utils.LoadUnencryptedDecryptionKey(decryptionKeyPath)
	assert.Nil(t, err)
	certificate, err := utils.LoadEncryptionCertificate(certificatePath)
	assert.Nil(t, err)

	configBuilder := jwe.NewJWEConfigBuilder()
	jweConfig := configBuilder.WithDecryptionKey(decryptionKey).
		WithCertificate(certificate).
		Build()

	assert.Equal(t, "761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79", jweConfig.GetEncryptionKeyFingerprint())
}
