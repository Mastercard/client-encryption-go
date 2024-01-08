package mastercard_encryption

import (
	"github.com/mastercard/client-encryption-go/field_level_encryption"
	"github.com/mastercard/client-encryption-go/utils"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestEncryptDecryptPayloadWithRootLevelEncryption(t *testing.T) {
	payload := `{"privateData":{"sensitiveData":{"pciData":"123"}},"publicData":"ABC"}`

	decryptionKeyPath := "../testdata/keys/pkcs8/test_key_pkcs8-2048.der"
	certificatePath := "../testdata/certificates/test_certificate-2048.der"

	decryptionKey, err := utils.LoadUnencryptedDecryptionKey(decryptionKeyPath)
	assert.Nil(t, err)
	certificate, err := utils.LoadEncryptionCertificate(certificatePath)
	assert.Nil(t, err)

	fingerprint := "761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79"

	cb := field_level_encryption.NewFieldLevelEncryptionConfigBuilder()
	flConfig, _ := cb.WithEncryptionCertificate(certificate).
		WithDecryptionKey(decryptionKey).
		WithEncryptionPath("$", "$").
		WithDecryptionPath("$", "$").
		WithOaepPaddingDigestAlgorithm(field_level_encryption.SHA256).
		WithEncryptedValueFieldName("encryptedValue").
		WithEncryptedKeyFieldName("encryptedKey").
		WithIvFieldName("iv").
		WithEncryptionKeyFingerprint(fingerprint).
		WithEncryptionKeyFingerprintFieldName("publicKeyFingerprint").
		WithOaepPaddingDigestAlgorithmFieldName("oaepPaddingDigestAlgorithm").
		WithFieldValueEncoding(field_level_encryption.HEX).
		Build()

	encryptedPayload := EncryptPayload(payload, *flConfig)
	assert.True(t, encryptedPayload != payload)

	decryptedPayload := DecryptPayload(encryptedPayload, *flConfig)
	assert.True(t, decryptedPayload == payload)
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
	flConfig, _ := cb.WithEncryptionCertificate(certificate).
		WithDecryptionKey(decryptionKey).
		WithEncryptionPath("$", "$").
		WithDecryptionPath("$", "$").
		WithOaepPaddingDigestAlgorithm(field_level_encryption.SHA256).
		WithEncryptedValueFieldName("encryptedValue").
		WithEncryptedKeyFieldName("encryptedKey").
		WithIvFieldName("iv").
		WithEncryptionKeyFingerprint(fingerprint).
		WithEncryptionKeyFingerprintFieldName("publicKeyFingerprint").
		WithOaepPaddingDigestAlgorithmFieldName("oaepPaddingDigestAlgorithm").
		WithFieldValueEncoding(field_level_encryption.HEX).
		Build()

	encryptedPayload := EncryptPayload(payload, *flConfig)
	assert.True(t, encryptedPayload != payload)

	decryptedPayload := DecryptPayload(encryptedPayload, *flConfig)
	assert.True(t, decryptedPayload == payload)
}

func TestEncryptDecryptPayloadWithHex(t *testing.T) {
	payload := `{"privateData":{"sensitiveData":{"pciData":"123"}},"publicData":"ABC"}`

	decryptionKeyPath := "../testdata/keys/pkcs8/test_key_pkcs8-2048.der"
	certificatePath := "../testdata/certificates/test_certificate-2048.der"

	decryptionKey, err := utils.LoadUnencryptedDecryptionKey(decryptionKeyPath)
	assert.Nil(t, err)
	certificate, err := utils.LoadEncryptionCertificate(certificatePath)
	assert.Nil(t, err)

	fingerprint := "761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79"

	cb := field_level_encryption.NewFieldLevelEncryptionConfigBuilder()
	flConfig, _ := cb.WithEncryptionCertificate(certificate).
		WithDecryptionKey(decryptionKey).
		WithEncryptionPath("privateData.sensitiveData", "privateData.encryptedData").
		WithDecryptionPath("privateData.encryptedData", "privateData.sensitiveData").
		WithOaepPaddingDigestAlgorithm(field_level_encryption.SHA256).
		WithEncryptedValueFieldName("encryptedValue").
		WithEncryptedKeyFieldName("encryptedKey").
		WithIvFieldName("iv").
		WithEncryptionKeyFingerprint(fingerprint).
		WithEncryptionKeyFingerprintFieldName("publicKeyFingerprint").
		WithOaepPaddingDigestAlgorithmFieldName("oaepPaddingDigestAlgorithm").
		WithFieldValueEncoding(field_level_encryption.HEX).
		Build()

	encryptedPayload := EncryptPayload(payload, *flConfig)
	assert.True(t, encryptedPayload != payload)

	decryptedPayload := DecryptPayload(encryptedPayload, *flConfig)
	assert.True(t, decryptedPayload == payload)
}

func TestEncryptDecryptPayloadWithBase64(t *testing.T) {
	payload := `{"privateData":{"sensitiveData":{"pciData":"123"}},"publicData":"ABC"}`

	decryptionKeyPath := "../testdata/keys/pkcs8/test_key_pkcs8-2048.der"
	certificatePath := "../testdata/certificates/test_certificate-2048.der"

	decryptionKey, err := utils.LoadUnencryptedDecryptionKey(decryptionKeyPath)
	assert.Nil(t, err)
	certificate, err := utils.LoadEncryptionCertificate(certificatePath)
	assert.Nil(t, err)

	fingerprint := "761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79"

	cb := field_level_encryption.NewFieldLevelEncryptionConfigBuilder()
	flConfig, _ := cb.WithEncryptionCertificate(certificate).
		WithDecryptionKey(decryptionKey).
		WithEncryptionPath("privateData.sensitiveData", "privateData.encryptedData").
		WithDecryptionPath("privateData.encryptedData", "privateData.sensitiveData").
		WithOaepPaddingDigestAlgorithm(field_level_encryption.SHA256).
		WithEncryptedValueFieldName("encryptedValue").
		WithEncryptedKeyFieldName("encryptedKey").
		WithIvFieldName("iv").
		WithEncryptionKeyFingerprint(fingerprint).
		WithEncryptionKeyFingerprintFieldName("publicKeyFingerprint").
		WithOaepPaddingDigestAlgorithmFieldName("oaepPaddingDigestAlgorithm").
		WithFieldValueEncoding(field_level_encryption.BASE64).
		Build()

	encryptedPayload := EncryptPayload(payload, *flConfig)
	assert.True(t, encryptedPayload != payload)

	decryptedPayload := DecryptPayload(encryptedPayload, *flConfig)
	assert.True(t, decryptedPayload == payload)
}

func TestEncryptDecryptPayloadWithSHA512(t *testing.T) {
	payload := `{"privateData":{"sensitiveData":{"pciData":"123"}},"publicData":"ABC"}`

	decryptionKeyPath := "../testdata/keys/pkcs8/test_key_pkcs8-2048.der"
	certificatePath := "../testdata/certificates/test_certificate-2048.der"

	decryptionKey, err := utils.LoadUnencryptedDecryptionKey(decryptionKeyPath)
	assert.Nil(t, err)
	certificate, err := utils.LoadEncryptionCertificate(certificatePath)
	assert.Nil(t, err)

	fingerprint := "761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79"

	cb := field_level_encryption.NewFieldLevelEncryptionConfigBuilder()
	flConfig, _ := cb.WithEncryptionCertificate(certificate).
		WithDecryptionKey(decryptionKey).
		WithEncryptionPath("privateData.sensitiveData", "privateData.encryptedData").
		WithDecryptionPath("privateData.encryptedData", "privateData.sensitiveData").
		WithOaepPaddingDigestAlgorithm(field_level_encryption.SHA512).
		WithEncryptedValueFieldName("encryptedValue").
		WithEncryptedKeyFieldName("encryptedKey").
		WithIvFieldName("iv").
		WithEncryptionKeyFingerprint(fingerprint).
		WithEncryptionKeyFingerprintFieldName("publicKeyFingerprint").
		WithOaepPaddingDigestAlgorithmFieldName("oaepPaddingDigestAlgorithm").
		WithFieldValueEncoding(field_level_encryption.HEX).
		Build()

	encryptedPayload := EncryptPayload(payload, *flConfig)
	assert.True(t, encryptedPayload != payload)

	decryptedPayload := DecryptPayload(encryptedPayload, *flConfig)
	assert.True(t, decryptedPayload == payload)
}
