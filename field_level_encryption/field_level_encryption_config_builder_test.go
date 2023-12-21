package field_level_encryption_test

import (
	"github.com/mastercard/client-encryption-go/field_level_encryption"
	"github.com/mastercard/client-encryption-go/utils"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestConfigBuildWithNoOaepPaddingDigestAlgorithm(t *testing.T) {
	decryptionKeyPath := "../testdata/keys/pkcs8/test_key_pkcs8-2048.der"
	certificatePath := "../testdata/certificates/test_certificate-2048.der"

	decryptionKey, err := utils.LoadUnencryptedDecryptionKey(decryptionKeyPath)
	assert.Nil(t, err)
	certificate, err := utils.LoadEncryptionCertificate(certificatePath)
	assert.Nil(t, err)

	fingerprint := "761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79"
	cb := field_level_encryption.NewFieldLevelEncryptionConfigBuilder()

	_, configError := cb.WithEncryptionCertificate(certificate).
		WithDecryptionKey(decryptionKey).
		WithEncryptionPath("privateData.sensitiveData", "privateData.encryptedData").
		WithDecryptionPath("privateData.encryptedData", "privateData.sensitiveData").
		WithEncryptedValueFieldName("encryptedValue").
		WithEncryptedKeyFieldName("encryptedKey").
		WithIvFieldName("iv").
		WithEncryptionKeyFingerprint(fingerprint).
		WithEncryptionKeyFingerprintFieldName("publicKeyFingerprint").
		WithOaepPaddingDigestAlgorithmFieldName("oaepPaddingDigestAlgorithm").
		WithFieldValueEncoding(field_level_encryption.HEX).
		Build()

	assert.True(t, configError.Error() == "the digest algorithm for OAEP must be set")
}

func TestConfigBuildShouldCalculateFingerprintWhenNotSet(t *testing.T) {
	decryptionKeyPath := "../testdata/keys/pkcs8/test_key_pkcs8-2048.der"
	certificatePath := "../testdata/certificates/test_certificate-2048.der"

	decryptionKey, err := utils.LoadUnencryptedDecryptionKey(decryptionKeyPath)
	assert.Nil(t, err)
	certificate, err := utils.LoadEncryptionCertificate(certificatePath)
	assert.Nil(t, err)

	cb := field_level_encryption.NewFieldLevelEncryptionConfigBuilder()

	config, _ := cb.WithEncryptionCertificate(certificate).
		WithDecryptionKey(decryptionKey).
		WithEncryptionPath("privateData.sensitiveData", "privateData.encryptedData").
		WithDecryptionPath("privateData.encryptedData", "privateData.sensitiveData").
		WithOaepPaddingDigestAlgorithm(field_level_encryption.SHA512).
		WithEncryptedValueFieldName("encryptedValue").
		WithEncryptedKeyFieldName("encryptedKey").
		WithIvFieldName("iv").
		WithEncryptionKeyFingerprintFieldName("publicKeyFingerprint").
		WithOaepPaddingDigestAlgorithmFieldName("oaepPaddingDigestAlgorithm").
		WithFieldValueEncoding(field_level_encryption.HEX).
		Build()

	assert.True(t, config.GetEncryptionCertificateFingerprint() == "80810fc13a8319fcf0e2ec322c82a4c304b782cc3ce671176343cfe8160c2279")
}

func TestConfigBuildWithUnsupportedAlgorithm(t *testing.T) {
	decryptionKeyPath := "../testdata/keys/pkcs8/test_key_pkcs8-2048.der"
	certificatePath := "../testdata/certificates/test_certificate-2048.der"

	decryptionKey, err := utils.LoadUnencryptedDecryptionKey(decryptionKeyPath)
	assert.Nil(t, err)
	certificate, err := utils.LoadEncryptionCertificate(certificatePath)
	assert.Nil(t, err)

	cb := field_level_encryption.NewFieldLevelEncryptionConfigBuilder()
	fingerprint := "761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79"

	_, configError := cb.WithEncryptionCertificate(certificate).
		WithDecryptionKey(decryptionKey).
		WithEncryptionPath("privateData.sensitiveData", "privateData.encryptedData").
		WithDecryptionPath("privateData.encryptedData", "privateData.sensitiveData").
		WithOaepPaddingDigestAlgorithm("SHA1").
		WithEncryptedValueFieldName("encryptedValue").
		WithEncryptedKeyFieldName("encryptedKey").
		WithIvFieldName("iv").
		WithEncryptionKeyFingerprint(fingerprint).
		WithEncryptionKeyFingerprintFieldName("publicKeyFingerprint").
		WithOaepPaddingDigestAlgorithmFieldName("oaepPaddingDigestAlgorithm").
		WithFieldValueEncoding(field_level_encryption.HEX).
		Build()

	assert.True(t, configError.Error() == "unsupported OAEP digest algorithm")
}

func TestConfigBuildWithNoFieldValueEncoding(t *testing.T) {
	decryptionKeyPath := "../testdata/keys/pkcs8/test_key_pkcs8-2048.der"
	certificatePath := "../testdata/certificates/test_certificate-2048.der"

	decryptionKey, err := utils.LoadUnencryptedDecryptionKey(decryptionKeyPath)
	assert.Nil(t, err)
	certificate, err := utils.LoadEncryptionCertificate(certificatePath)
	assert.Nil(t, err)

	cb := field_level_encryption.NewFieldLevelEncryptionConfigBuilder()
	fingerprint := "761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79"

	_, configError := cb.WithEncryptionCertificate(certificate).
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
		Build()

	assert.True(t, configError.Error() == "field value encoding must be set")
}

func TestConfigBuildWithNoIvFieldName(t *testing.T) {
	decryptionKeyPath := "../testdata/keys/pkcs8/test_key_pkcs8-2048.der"
	certificatePath := "../testdata/certificates/test_certificate-2048.der"

	decryptionKey, err := utils.LoadUnencryptedDecryptionKey(decryptionKeyPath)
	assert.Nil(t, err)
	certificate, err := utils.LoadEncryptionCertificate(certificatePath)
	assert.Nil(t, err)

	cb := field_level_encryption.NewFieldLevelEncryptionConfigBuilder()
	fingerprint := "761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79"

	_, configError := cb.WithEncryptionCertificate(certificate).
		WithDecryptionKey(decryptionKey).
		WithEncryptionPath("privateData.sensitiveData", "privateData.encryptedData").
		WithDecryptionPath("privateData.encryptedData", "privateData.sensitiveData").
		WithOaepPaddingDigestAlgorithm(field_level_encryption.SHA256).
		WithEncryptedValueFieldName("encryptedValue").
		WithEncryptedKeyFieldName("encryptedKey").
		WithEncryptionKeyFingerprint(fingerprint).
		WithEncryptionKeyFingerprintFieldName("publicKeyFingerprint").
		WithOaepPaddingDigestAlgorithmFieldName("oaepPaddingDigestAlgorithm").
		WithFieldValueEncoding(field_level_encryption.HEX).
		Build()

	assert.True(t, configError.Error() == "iv field name must be set")
}

func TestConfigBuildWithNoEncryptedKeyFieldName(t *testing.T) {
	decryptionKeyPath := "../testdata/keys/pkcs8/test_key_pkcs8-2048.der"
	certificatePath := "../testdata/certificates/test_certificate-2048.der"

	decryptionKey, err := utils.LoadUnencryptedDecryptionKey(decryptionKeyPath)
	assert.Nil(t, err)
	certificate, err := utils.LoadEncryptionCertificate(certificatePath)
	assert.Nil(t, err)

	cb := field_level_encryption.NewFieldLevelEncryptionConfigBuilder()
	fingerprint := "761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79"

	_, configError := cb.WithEncryptionCertificate(certificate).
		WithDecryptionKey(decryptionKey).
		WithEncryptionPath("privateData.sensitiveData", "privateData.encryptedData").
		WithDecryptionPath("privateData.encryptedData", "privateData.sensitiveData").
		WithOaepPaddingDigestAlgorithm(field_level_encryption.SHA256).
		WithEncryptedValueFieldName("encryptedValue").
		WithIvFieldName("iv").
		WithEncryptionKeyFingerprint(fingerprint).
		WithEncryptionKeyFingerprintFieldName("publicKeyFingerprint").
		WithOaepPaddingDigestAlgorithmFieldName("oaepPaddingDigestAlgorithm").
		WithFieldValueEncoding(field_level_encryption.HEX).
		Build()

	assert.True(t, configError.Error() == "encrypted key field name must be set")
}

func TestConfigBuildWithNoEncryptedValueFieldName(t *testing.T) {
	decryptionKeyPath := "../testdata/keys/pkcs8/test_key_pkcs8-2048.der"
	certificatePath := "../testdata/certificates/test_certificate-2048.der"

	decryptionKey, err := utils.LoadUnencryptedDecryptionKey(decryptionKeyPath)
	assert.Nil(t, err)
	certificate, err := utils.LoadEncryptionCertificate(certificatePath)
	assert.Nil(t, err)

	cb := field_level_encryption.NewFieldLevelEncryptionConfigBuilder()
	fingerprint := "761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79"

	_, configError := cb.WithEncryptionCertificate(certificate).
		WithDecryptionKey(decryptionKey).
		WithEncryptionPath("privateData.sensitiveData", "privateData.encryptedData").
		WithDecryptionPath("privateData.encryptedData", "privateData.sensitiveData").
		WithOaepPaddingDigestAlgorithm(field_level_encryption.SHA256).
		WithEncryptedKeyFieldName("encryptedKey").
		WithIvFieldName("iv").
		WithEncryptionKeyFingerprint(fingerprint).
		WithEncryptionKeyFingerprintFieldName("publicKeyFingerprint").
		WithOaepPaddingDigestAlgorithmFieldName("oaepPaddingDigestAlgorithm").
		WithFieldValueEncoding(field_level_encryption.HEX).
		Build()

	assert.True(t, configError.Error() == "encrypted value field name must be set")
}
