package field_level_encryption

import (
	"crypto/rsa"
	"crypto/x509"
)

type FieldLevelEncryptionConfig struct {
	encryptionCertificateFingerprint           string
	oaepPaddingDigestAlgorithm                 string
	oaepPaddingDigestAlgorithmFieldName        string
	oaepPaddingDigestAlgorithmHeaderName       string
	ivFieldName                                string
	ivHeaderName                               string
	encryptedKeyFieldName                      string
	encryptedKeyHeaderName                     string
	encryptionCertificateFingerprintFieldName  string
	encryptionCertificateFingerprintHeaderName string
	encryptionKeyFingerprintFieldName          string
	encryptionKeyFingerprintHeaderName         string
	fieldValueEncoding                         string

	decryptionKey            *rsa.PrivateKey
	encryptionCertificate    *x509.Certificate
	encryptionKey            *rsa.PublicKey
	encryptionKeyFingerprint string
	encryptedValueFieldName  string
	encryptionPaths          map[string]string
	decryptionPaths          map[string]string
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
