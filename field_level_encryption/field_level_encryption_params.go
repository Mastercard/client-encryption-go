package field_level_encryption

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"github.com/mastercard/client-encryption-go/aes_encryption"
	"github.com/mastercard/client-encryption-go/utils"
)

type FieldLevelEncryptionParams struct {
	SymmetricKeySize                int
	SymmetricKeyType                string
	IvValue                         string
	EncryptedKeyValue               string
	OaepPaddingDigestAlgorithmValue string
	Config                          FieldLevelEncryptionConfig
	SecretKey                       []byte
	IvParameterSpec                 []byte
}

func NewFieldLevelEncryptionParams(ivValue string, encryptedKeyValue string, oaepPaddingDigestAlgorithmValue string, config FieldLevelEncryptionConfig) *FieldLevelEncryptionParams {
	flep := FieldLevelEncryptionParams{}
	flep.SymmetricKeySize = 128
	flep.SymmetricKeyType = "AES"

	flep.IvValue = ivValue
	flep.EncryptedKeyValue = encryptedKeyValue
	flep.OaepPaddingDigestAlgorithmValue = oaepPaddingDigestAlgorithmValue
	flep.Config = config

	return &flep
}

func Generate(config FieldLevelEncryptionConfig) *FieldLevelEncryptionParams {
	//// Generate a random IV
	ivParameterSpec := aes_encryption.GenerateCEK(16 * 8)
	ivSpecValue := utils.EncodeData(ivParameterSpec, config.GetFieldValueEncoding())

	//Generate an AES secret key
	secretKey := aes_encryption.GenerateCEK(128)

	//Get Oaep Padding Algorithm
	oaepPaddingDigestAlgorithm := config.GetOaepPaddingDigestAlgorithm()

	//Encrypt the secret key
	var encryptedKey []byte
	if oaepPaddingDigestAlgorithm == "SHA256" {
		encryptedKey, _ = rsa.EncryptOAEP(sha256.New(), rand.Reader, config.GetEncryptionCertificate().PublicKey.(*rsa.PublicKey), secretKey, nil)
	} else {
		encryptedKey, _ = rsa.EncryptOAEP(sha512.New(), rand.Reader, config.GetEncryptionCertificate().PublicKey.(*rsa.PublicKey), secretKey, nil)
	}
	encryptedKeyValue := utils.EncodeData(encryptedKey, config.GetFieldValueEncoding())

	params := NewFieldLevelEncryptionParams(ivSpecValue, encryptedKeyValue, oaepPaddingDigestAlgorithm, config)
	params.SecretKey = secretKey
	params.IvParameterSpec = ivParameterSpec
	return params
}
