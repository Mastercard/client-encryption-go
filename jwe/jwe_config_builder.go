package jwe

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
)

type JWEConfigBuilder struct {
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

func NewJWEConfigBuilder() *JWEConfigBuilder {
	cb := JWEConfigBuilder{}
	cb.encryptionPaths = make(map[string]string)
	cb.decryptionPaths = make(map[string]string)

	return &cb
}

func (cb *JWEConfigBuilder) WithDecryptionKey(decryptionKey *rsa.PrivateKey) *JWEConfigBuilder {
	cb.decryptionKey = decryptionKey
	return cb
}

func (cb *JWEConfigBuilder) WithCertificate(certificate *x509.Certificate) *JWEConfigBuilder {
	if cb.encryptionKey != nil {
		panic("Error: cannot use both withCertificate and withEncryptionKey methods together!")
	}
	cb.certificate = certificate
	cb.encryptionKey = certificate.PublicKey.(*rsa.PublicKey)
	return cb
}

func (cb *JWEConfigBuilder) WithEncryptionKey(encryptionKey *rsa.PublicKey) *JWEConfigBuilder {
	if cb.encryptionKey != nil {
		panic("Error: cannot use both withCertificate and withEncryptionKey methods together!")
	}
	cb.encryptionKey = encryptionKey
	return cb
}

func (cb *JWEConfigBuilder) WithCek(cek []byte) *JWEConfigBuilder {
	cb.cek = cek
	return cb
}

func (cb *JWEConfigBuilder) WithIv(iv []byte) *JWEConfigBuilder {
	cb.iv = iv
	return cb
}

func (cb *JWEConfigBuilder) WithEncryptionPath(jsonPathIn, jsonPathOut string) *JWEConfigBuilder {
	cb.encryptionPaths[jsonPathIn] = jsonPathOut
	return cb
}

func (cb *JWEConfigBuilder) WithDecryptionPath(jsonPathIn, jsonPathOut string) *JWEConfigBuilder {
	cb.decryptionPaths[jsonPathIn] = jsonPathOut
	return cb
}

func (cb *JWEConfigBuilder) WithEncryptedValueFieldName(encryptedValueFieldName string) *JWEConfigBuilder {
	cb.encryptedValueFieldName = encryptedValueFieldName
	return cb
}

func (cb *JWEConfigBuilder) computeKeyFingerprint() {
	derEncoded, err := x509.MarshalPKIXPublicKey(cb.encryptionKey)
	if err != nil {
		panic(err)
	}
	fingerprint := sha256.Sum256(derEncoded)
	cb.encryptionKeyFingerprint = hex.EncodeToString([]byte(fingerprint[:]))
}

func (cb *JWEConfigBuilder) Build() *JWEConfig {
	cb.computeKeyFingerprint()

	if cb.encryptedValueFieldName == "" {
		cb.encryptedValueFieldName = "encryptedData"
	}

	return &JWEConfig{
		decryptionKey:            cb.decryptionKey,
		certificate:              cb.certificate,
		encryptedValueFieldName:  cb.encryptedValueFieldName,
		encryptionKey:            cb.encryptionKey,
		cek:                      cb.cek,
		iv:                       cb.iv,
		encryptionPaths:          cb.encryptionPaths,
		decryptionPaths:          cb.decryptionPaths,
		encryptionKeyFingerprint: cb.encryptionKeyFingerprint,
	}
}
