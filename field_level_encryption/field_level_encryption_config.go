package field_level_encryption

import (
	"crypto/rsa"
	"crypto/x509"
)

type FieldLevelEncryptionConfig struct {
	encryptionCertificateFingerprint          string
	oaepPaddingDigestAlgorithm                string
	oaepPaddingDigestAlgorithmFieldName       string
	ivFieldName                               string
	ivHeaderName                              string
	encryptedKeyFieldName                     string
	encryptedKeyHeaderName                    string
	encryptionCertificateFingerprintFieldName string
	encryptionKeyFingerprintFieldName         string
	fieldValueEncoding                        string

	decryptionKey            *rsa.PrivateKey
	encryptionCertificate    *x509.Certificate
	encryptionKey            *rsa.PublicKey
	encryptionKeyFingerprint string
	encryptedValueFieldName  string
	encryptionPaths          map[string]string
	decryptionPaths          map[string]string
}

const (
	SHA256 = "SHA256"
	SHA512 = "SHA512"
	HEX    = "HEX"
	BASE64 = "BASE64"
)

func (config *FieldLevelEncryptionConfig) GetOaepPaddingDigestAlgorithmFieldName() string {
	return config.oaepPaddingDigestAlgorithmFieldName
}

func (config *FieldLevelEncryptionConfig) GetEncryptionCertificateFingerprint() string {
	return config.encryptionCertificateFingerprint
}

func (config *FieldLevelEncryptionConfig) GetEncryptionCertificateFingerprintFieldName() string {
	return config.encryptionCertificateFingerprintFieldName
}

func (config *FieldLevelEncryptionConfig) GetIvFieldName() string {
	return config.ivFieldName
}

func (config *FieldLevelEncryptionConfig) GetEncryptedKeyFieldName() string {
	return config.encryptedKeyFieldName
}

func (config *FieldLevelEncryptionConfig) GetEncryptionKeyFingerprintFieldName() string {
	return config.encryptionKeyFingerprintFieldName
}

func (config *FieldLevelEncryptionConfig) GetDecryptionKey() *rsa.PrivateKey {
	return config.decryptionKey
}

func (config *FieldLevelEncryptionConfig) GetEncryptionCertificate() *x509.Certificate {
	return config.encryptionCertificate
}

func (config *FieldLevelEncryptionConfig) GetEncryptedValueFieldName() string {
	return config.encryptedValueFieldName
}

func (config *FieldLevelEncryptionConfig) GetFieldValueEncoding() string {
	return config.fieldValueEncoding
}

func (config *FieldLevelEncryptionConfig) GetOaepPaddingDigestAlgorithm() string {
	return config.oaepPaddingDigestAlgorithm
}

func (config *FieldLevelEncryptionConfig) GetEncryptionKey() *rsa.PublicKey {
	return config.encryptionKey
}

func (config *FieldLevelEncryptionConfig) GetEncryptionPaths() map[string]string {
	return config.encryptionPaths
}

func (config *FieldLevelEncryptionConfig) GetDecryptionPaths() map[string]string {
	return config.decryptionPaths
}

func (config *FieldLevelEncryptionConfig) GetEncryptionKeyFingerprint() string {
	return config.encryptionKeyFingerprint
}
