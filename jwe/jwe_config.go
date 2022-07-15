package jwe

import (
	"crypto/rsa"
	"crypto/x509"
)

type JWEConfig struct {
	decryptionKey            *rsa.PrivateKey
	certificate              *x509.Certificate
	encryptedValueFieldName  string
	encryptionKey            *rsa.PublicKey
	cek                      []byte
	iv                       []byte
	encryptionPaths          map[string]string
	decryptionPaths          map[string]string
	encryptionKeyFingerprint string
}

func (config *JWEConfig) GetDecryptionKey() *rsa.PrivateKey {
	return config.decryptionKey
}

func (config *JWEConfig) GetCertificate() *x509.Certificate {
	return config.certificate
}

func (config *JWEConfig) GetEncryptedValueFieldName() string {
	return config.encryptedValueFieldName
}

func (config *JWEConfig) GetEncryptionKey() *rsa.PublicKey {
	return config.encryptionKey
}

func (config *JWEConfig) GetCek() []byte {
	return config.cek
}

func (config *JWEConfig) GetIv() []byte {
	return config.iv
}

func (config *JWEConfig) GetEncryptionPaths() map[string]string {
	return config.encryptionPaths
}

func (config *JWEConfig) GetDecryptionPaths() map[string]string {
	return config.decryptionPaths
}

func (config *JWEConfig) GetEncryptionKeyFingerprint() string {
	return config.encryptionKeyFingerprint
}
