package field_level_encryption

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
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
	ivSpecValue := utils.HexUrlEncode(ivParameterSpec)

	//Generate an AES secret key
	secretKey := aes_encryption.GenerateCEK(128)

	//Encrypt the secret key
	encryptedKey, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, config.GetEncryptionCertificate().PublicKey.(*rsa.PublicKey), secretKey, nil)
	encryptedKeyValue := utils.HexUrlEncode(encryptedKey)

	params := NewFieldLevelEncryptionParams(ivSpecValue, encryptedKeyValue, "SHA256", config)
	params.SecretKey = secretKey
	params.IvParameterSpec = ivParameterSpec
	return params
}
