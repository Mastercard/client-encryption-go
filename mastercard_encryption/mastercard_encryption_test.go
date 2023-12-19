package mastercard_encryption

import (
	"fmt"
	"github.com/mastercard/client-encryption-go/field_level_encryption"
	"github.com/mastercard/client-encryption-go/utils"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestEncryptDecryptPayloadWithRootLevelEncryption(t *testing.T) {
	payload := `{
  		"publicData": "ABC",
		"privateData": {
			"sensitiveData": {
				"pciData": "123"
			}
		}
	}`

	decryptionKeyPath := "../testdata/keys/pkcs8/test_key_pkcs8-2048.der"
	certificatePath := "../testdata/certificates/test_certificate-2048.der"

	decryptionKey, err := utils.LoadUnencryptedDecryptionKey(decryptionKeyPath)
	assert.Nil(t, err)
	certificate, err := utils.LoadEncryptionCertificate(certificatePath)
	assert.Nil(t, err)

	fingerprint := "761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79"

	cb := field_level_encryption.NewFieldLevelEncryptionConfigBuilder()
	flConfig := cb.WithEncryptionCertificate(certificate).
		WithDecryptionKey(decryptionKey).
		WithEncryptionPath("$", "$").
		WithDecryptionPath("$", "$").
		WithOaepPaddingDigestAlgorithm("SHA-256").
		WithEncryptedValueFieldName("encryptedValue").
		WithEncryptedKeyFieldName("encryptedKey").
		WithIvFieldName("iv").
		WithEncryptionKeyFingerprint(fingerprint).
		WithEncryptionKeyFingerprintFieldName("publicKeyFingerprint").
		WithOaepPaddingDigestAlgorithmFieldName("oaepPaddingDigestAlgorithm").
		WithFieldValueEncoding("HEX").
		Build()

	encryptedPayload := EncryptPayload(payload, *flConfig)
	fmt.Println(encryptedPayload)

	decryptedPayload := DecryptPayload(encryptedPayload, *flConfig)
	fmt.Println(decryptedPayload)
}

func TestEncryptDecryptPayloadWithRootLevelArrayEncryption(t *testing.T) {
	payload := `[]`

	decryptionKeyPath := "../testdata/keys/pkcs8/test_key_pkcs8-2048.der"
	certificatePath := "../testdata/certificates/test_certificate-2048.der"

	decryptionKey, err := utils.LoadUnencryptedDecryptionKey(decryptionKeyPath)
	assert.Nil(t, err)
	certificate, err := utils.LoadEncryptionCertificate(certificatePath)
	assert.Nil(t, err)

	fingerprint := "761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79"

	cb := field_level_encryption.NewFieldLevelEncryptionConfigBuilder()
	flConfig := cb.WithEncryptionCertificate(certificate).
		WithDecryptionKey(decryptionKey).
		WithEncryptionPath("$", "$").
		WithDecryptionPath("$", "$").
		WithOaepPaddingDigestAlgorithm("SHA-256").
		WithEncryptedValueFieldName("encryptedValue").
		WithEncryptedKeyFieldName("encryptedKey").
		WithIvFieldName("iv").
		WithEncryptionKeyFingerprint(fingerprint).
		WithEncryptionKeyFingerprintFieldName("publicKeyFingerprint").
		WithOaepPaddingDigestAlgorithmFieldName("oaepPaddingDigestAlgorithm").
		WithFieldValueEncoding("HEX").
		Build()

	encryptedPayload := EncryptPayload(payload, *flConfig)
	fmt.Println(encryptedPayload)

	decryptedPayload := DecryptPayload(encryptedPayload, *flConfig)
	fmt.Println(decryptedPayload)
}

func TestEncryptDecryptPayloadWithHex(t *testing.T) {
	payload := `{
  		"publicData": "ABC",
		"privateData": {
			"sensitiveData": {
				"pciData": "123"
			}
		}
	}`

	decryptionKeyPath := "../testdata/keys/pkcs8/test_key_pkcs8-2048.der"
	certificatePath := "../testdata/certificates/test_certificate-2048.der"

	decryptionKey, err := utils.LoadUnencryptedDecryptionKey(decryptionKeyPath)
	assert.Nil(t, err)
	certificate, err := utils.LoadEncryptionCertificate(certificatePath)
	assert.Nil(t, err)

	fingerprint := "761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79"

	cb := field_level_encryption.NewFieldLevelEncryptionConfigBuilder()
	flConfig := cb.WithEncryptionCertificate(certificate).
		WithDecryptionKey(decryptionKey).
		WithEncryptionPath("privateData.sensitiveData", "privateData.encryptedData").
		WithDecryptionPath("privateData.encryptedData", "privateData.sensitiveData").
		WithOaepPaddingDigestAlgorithm("SHA-256").
		WithEncryptedValueFieldName("encryptedValue").
		WithEncryptedKeyFieldName("encryptedKey").
		WithIvFieldName("iv").
		WithEncryptionKeyFingerprint(fingerprint).
		WithEncryptionKeyFingerprintFieldName("publicKeyFingerprint").
		WithOaepPaddingDigestAlgorithmFieldName("oaepPaddingDigestAlgorithm").
		WithFieldValueEncoding("HEX").
		Build()

	encryptedPayload := EncryptPayload(payload, *flConfig)
	fmt.Println(encryptedPayload)

	decryptedPayload := DecryptPayload(encryptedPayload, *flConfig)
	fmt.Println(decryptedPayload)
}

func TestEncryptDecryptPayloadWithBase64(t *testing.T) {
	payload := `{
  		"publicData": "ABC",
		"privateData": {
			"sensitiveData": {
				"pciData": "123"
			}
		}
	}`

	decryptionKeyPath := "../testdata/keys/pkcs8/test_key_pkcs8-2048.der"
	certificatePath := "../testdata/certificates/test_certificate-2048.der"

	decryptionKey, err := utils.LoadUnencryptedDecryptionKey(decryptionKeyPath)
	assert.Nil(t, err)
	certificate, err := utils.LoadEncryptionCertificate(certificatePath)
	assert.Nil(t, err)

	fingerprint := "761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79"

	cb := field_level_encryption.NewFieldLevelEncryptionConfigBuilder()
	flConfig := cb.WithEncryptionCertificate(certificate).
		WithDecryptionKey(decryptionKey).
		WithEncryptionPath("privateData.sensitiveData", "privateData.encryptedData").
		WithDecryptionPath("privateData.encryptedData", "privateData.sensitiveData").
		WithOaepPaddingDigestAlgorithm("SHA-256").
		WithEncryptedValueFieldName("encryptedValue").
		WithEncryptedKeyFieldName("encryptedKey").
		WithIvFieldName("iv").
		WithEncryptionKeyFingerprint(fingerprint).
		WithEncryptionKeyFingerprintFieldName("publicKeyFingerprint").
		WithOaepPaddingDigestAlgorithmFieldName("oaepPaddingDigestAlgorithm").
		WithFieldValueEncoding("BASE64").
		Build()

	encryptedPayload := EncryptPayload(payload, *flConfig)
	fmt.Println(encryptedPayload)

	decryptedPayload := DecryptPayload(encryptedPayload, *flConfig)
	fmt.Println(decryptedPayload)
}

func TestEncryptDecryptPayloadWithSHA512(t *testing.T) {
	payload := `{
  		"publicData": "ABC",
		"privateData": {
			"sensitiveData": {
				"pciData": "123"
			}
		}
	}`

	decryptionKeyPath := "../testdata/keys/pkcs8/test_key_pkcs8-2048.der"
	certificatePath := "../testdata/certificates/test_certificate-2048.der"

	decryptionKey, err := utils.LoadUnencryptedDecryptionKey(decryptionKeyPath)
	assert.Nil(t, err)
	certificate, err := utils.LoadEncryptionCertificate(certificatePath)
	assert.Nil(t, err)

	fingerprint := "761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79"

	cb := field_level_encryption.NewFieldLevelEncryptionConfigBuilder()
	flConfig := cb.WithEncryptionCertificate(certificate).
		WithDecryptionKey(decryptionKey).
		WithEncryptionPath("privateData.sensitiveData", "privateData.encryptedData").
		WithDecryptionPath("privateData.encryptedData", "privateData.sensitiveData").
		WithOaepPaddingDigestAlgorithm("SHA-512").
		WithEncryptedValueFieldName("encryptedValue").
		WithEncryptedKeyFieldName("encryptedKey").
		WithIvFieldName("iv").
		WithEncryptionKeyFingerprint(fingerprint).
		WithEncryptionKeyFingerprintFieldName("publicKeyFingerprint").
		WithOaepPaddingDigestAlgorithmFieldName("oaepPaddingDigestAlgorithm").
		WithFieldValueEncoding("BASE64").
		Build()

	encryptedPayload := EncryptPayload(payload, *flConfig)
	fmt.Println(encryptedPayload)

	decryptedPayload := DecryptPayload(encryptedPayload, *flConfig)
	fmt.Println(decryptedPayload)
}
