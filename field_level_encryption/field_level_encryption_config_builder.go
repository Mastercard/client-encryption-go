package field_level_encryption

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
)

type FieldLevelEncryptionConfigBuilder struct {
	encryptionCertificateFingerprint          string
	oaepPaddingDigestAlgorithm                string
	ivFieldName                               string
	ivHeaderName                              string
	oaepPaddingDigestAlgorithmFieldName       string
	encryptedKeyFieldName                     string
	encryptionCertificateFingerprintFieldName string
	encryptionKeyFingerprintFieldName         string

	encryptionCertificate    *x509.Certificate
	encryptionKeyFingerprint string
	decryptionKey            *rsa.PrivateKey
	fieldValueEncoding       string
	encryptionPaths          map[string]string
	decryptionPaths          map[string]string
	encryptedValueFieldName  string
}

func NewFieldLevelEncryptionConfigBuilder() *FieldLevelEncryptionConfigBuilder {
	cb := FieldLevelEncryptionConfigBuilder{}
	cb.encryptionPaths = make(map[string]string)
	cb.decryptionPaths = make(map[string]string)

	return &cb
}

func (cb *FieldLevelEncryptionConfigBuilder) WithEncryptionCertificate(encryptionCertificate *x509.Certificate) *FieldLevelEncryptionConfigBuilder {
	cb.encryptionCertificate = encryptionCertificate
	return cb
}

func (cb *FieldLevelEncryptionConfigBuilder) WithEncryptionCertificateFingerprint(encryptionCertificateFingerprint string) *FieldLevelEncryptionConfigBuilder {
	cb.encryptionCertificateFingerprint = encryptionCertificateFingerprint
	return cb
}

func (cb *FieldLevelEncryptionConfigBuilder) WithEncryptionKeyFingerprint(encryptionKeyFingerprint string) *FieldLevelEncryptionConfigBuilder {
	cb.encryptionKeyFingerprint = encryptionKeyFingerprint
	return cb
}
func (cb *FieldLevelEncryptionConfigBuilder) WithDecryptionKey(decryptionKey *rsa.PrivateKey) *FieldLevelEncryptionConfigBuilder {
	cb.decryptionKey = decryptionKey
	return cb
}

func (cb *FieldLevelEncryptionConfigBuilder) WithEncryptionPath(jsonPathIn string, jsonPathOut string) *FieldLevelEncryptionConfigBuilder {
	cb.encryptionPaths[jsonPathIn] = jsonPathOut
	return cb
}

func (cb *FieldLevelEncryptionConfigBuilder) WithDecryptionPath(jsonPathIn string, jsonPathOut string) *FieldLevelEncryptionConfigBuilder {
	cb.decryptionPaths[jsonPathIn] = jsonPathOut
	return cb
}

func (cb *FieldLevelEncryptionConfigBuilder) WithOaepPaddingDigestAlgorithm(oaepPaddingDigestAlgorithm string) *FieldLevelEncryptionConfigBuilder {
	cb.oaepPaddingDigestAlgorithm = oaepPaddingDigestAlgorithm
	return cb
}

func (cb *FieldLevelEncryptionConfigBuilder) WithIvFieldName(ivFieldName string) *FieldLevelEncryptionConfigBuilder {
	cb.ivFieldName = ivFieldName
	return cb
}

func (cb *FieldLevelEncryptionConfigBuilder) WithOaepPaddingDigestAlgorithmFieldName(oaepPaddingDigestAlgorithmFieldName string) *FieldLevelEncryptionConfigBuilder {
	cb.oaepPaddingDigestAlgorithmFieldName = oaepPaddingDigestAlgorithmFieldName
	return cb
}

func (cb *FieldLevelEncryptionConfigBuilder) WithEncryptedKeyFieldName(encryptedKeyFieldName string) *FieldLevelEncryptionConfigBuilder {
	cb.encryptedKeyFieldName = encryptedKeyFieldName
	return cb
}

func (cb *FieldLevelEncryptionConfigBuilder) WithEncryptedValueFieldName(encryptedValueFieldName string) *FieldLevelEncryptionConfigBuilder {
	cb.encryptedValueFieldName = encryptedValueFieldName
	return cb
}

func (cb *FieldLevelEncryptionConfigBuilder) WithEncryptionCertificateFingerprintFieldName(encryptionCertificateFingerprintFieldName string) *FieldLevelEncryptionConfigBuilder {
	cb.encryptionCertificateFingerprintFieldName = encryptionCertificateFingerprintFieldName
	return cb
}

func (cb *FieldLevelEncryptionConfigBuilder) WithEncryptionKeyFingerprintFieldName(encryptionKeyFingerprintFieldName string) *FieldLevelEncryptionConfigBuilder {
	cb.encryptionKeyFingerprintFieldName = encryptionKeyFingerprintFieldName
	return cb
}

func (cb *FieldLevelEncryptionConfigBuilder) WithFieldValueEncoding(fieldValueEncoding string) *FieldLevelEncryptionConfigBuilder {
	cb.fieldValueEncoding = fieldValueEncoding
	return cb
}

func (cb *FieldLevelEncryptionConfigBuilder) Build() (*FieldLevelEncryptionConfig, error) {
	if len(cb.oaepPaddingDigestAlgorithm) == 0 {
		return nil, errors.New("the digest algorithm for OAEP must be set")
	}

	if cb.oaepPaddingDigestAlgorithm != "SHA256" && cb.oaepPaddingDigestAlgorithm != "SHA512" {
		return nil, errors.New("unsupported OAEP digest algorithm")
	}

	if len(cb.fieldValueEncoding) == 0 {
		return nil, errors.New("field value encoding must be set")
	}

	if len(cb.ivFieldName) == 0 {
		return nil, errors.New("iv field name must be set")
	}

	if len(cb.encryptedKeyFieldName) == 0 {
		return nil, errors.New("encrypted key field name must be set")
	}

	if len(cb.encryptedValueFieldName) == 0 {
		return nil, errors.New("encrypted value field name must be set")
	}

	if len(cb.encryptionCertificateFingerprint) == 0 {
		cb.encryptionCertificateFingerprint = computeCertificateFingerprint(cb.encryptionCertificate)
	}

	return &FieldLevelEncryptionConfig{
		encryptionCertificateFingerprintFieldName: cb.encryptionCertificateFingerprintFieldName,
		encryptionKeyFingerprintFieldName:         cb.encryptionKeyFingerprintFieldName,
		encryptionCertificateFingerprint:          cb.encryptionCertificateFingerprint,
		encryptionKeyFingerprint:                  cb.encryptionKeyFingerprint,
		decryptionKey:                             cb.decryptionKey,
		encryptionPaths:                           cb.encryptionPaths,
		encryptionCertificate:                     cb.encryptionCertificate,
		oaepPaddingDigestAlgorithm:                cb.oaepPaddingDigestAlgorithm,
		ivFieldName:                               cb.ivFieldName,
		oaepPaddingDigestAlgorithmFieldName:       cb.oaepPaddingDigestAlgorithmFieldName,
		decryptionPaths:                           cb.decryptionPaths,
		encryptedKeyFieldName:                     cb.encryptedKeyFieldName,
		fieldValueEncoding:                        cb.fieldValueEncoding,
		encryptedValueFieldName:                   cb.encryptedValueFieldName,
	}, nil
}

func computeCertificateFingerprint(cert *x509.Certificate) string {
	fingerprint := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(fingerprint[:])
}
