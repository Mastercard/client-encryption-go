package mastercard_encryption

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"github.com/Jeffail/gabs/v2"
	"github.com/mastercard/client-encryption-go/aes_encryption"
	"github.com/mastercard/client-encryption-go/field_level_encryption"
	"github.com/mastercard/client-encryption-go/utils"
)

func EncryptPayload(payload string, config field_level_encryption.FieldLevelEncryptionConfig) string {
	jsonPayload, _ := gabs.ParseJSON([]byte(payload))
	for jsonPathIn, jsonPathOut := range config.GetEncryptionPaths() {
		jsonPayload = encryptPayloadPath(jsonPayload, jsonPathIn, jsonPathOut, config)
	}
	return jsonPayload.String()
}

func encryptPayloadPath(jsonPayload *gabs.Container, jsonPathIn string, jsonPathOut string,
	config field_level_encryption.FieldLevelEncryptionConfig) *gabs.Container {
	params := field_level_encryption.Generate(config)

	var payloadPath *gabs.Container
	if jsonPathIn == "$" {
		payloadPath = jsonPayload
	} else {
		payloadPath = jsonPayload.Path(jsonPathIn)
	}

	encryptedValueBytes, _, _ := aes_encryption.AesCbcEncrypt(payloadPath.Bytes(), params.SecretKey, params.IvParameterSpec, nil)
	payload := utils.EncodeData(encryptedValueBytes, config.GetFieldValueEncoding())

	encryptedObject := gabs.New()

	if !utils.IsNullOrEmpty(config.GetEncryptedValueFieldName()) {
		encryptedObject.Set(payload, config.GetEncryptedValueFieldName())
	}

	if !utils.IsNullOrEmpty(config.GetIvFieldName()) {
		encryptedObject.Set(params.IvValue, config.GetIvFieldName())
	}

	if !utils.IsNullOrEmpty(config.GetEncryptedKeyFieldName()) {
		encryptedObject.Set(params.EncryptedKeyValue, config.GetEncryptedKeyFieldName())
	}

	if !utils.IsNullOrEmpty(config.GetEncryptionKeyFingerprintFieldName()) {
		encryptedObject.Set(config.GetEncryptionKeyFingerprint(), config.GetEncryptionKeyFingerprintFieldName())
	}

	if !utils.IsNullOrEmpty(config.GetOaepPaddingDigestAlgorithmFieldName()) {
		encryptedObject.Set(params.OaepPaddingDigestAlgorithmValue, config.GetOaepPaddingDigestAlgorithmFieldName())
	}

	if jsonPathIn == "$" {
		jsonPayload = gabs.New()
		if jsonPathOut != "$" {
			jsonPayload.SetP(encryptedObject, jsonPathOut)
		} else {
			jsonPayload = encryptedObject
		}
	} else {
		jsonPayload.DeleteP(jsonPathIn)
		jsonPayload.SetP(encryptedObject, jsonPathOut)
	}

	return jsonPayload
}

func DecryptPayload(encryptedPayload string, config field_level_encryption.FieldLevelEncryptionConfig) string {
	jsonPayload, _ := gabs.ParseJSON([]byte(encryptedPayload))
	for jsonPathIn, jsonPathOut := range config.GetDecryptionPaths() {
		jsonPayload = decryptPayloadPath(jsonPayload, jsonPathIn, jsonPathOut, config)
	}
	return jsonPayload.String()
}

func decryptPayloadPath(jsonPayload *gabs.Container, jsonPathIn string, jsonPathOut string, config field_level_encryption.FieldLevelEncryptionConfig) *gabs.Container {
	var inJsonObject *gabs.Container

	if jsonPathIn == "$" {
		inJsonObject = jsonPayload
	} else {
		inJsonObject = jsonPayload.Path(jsonPathIn)
	}

	encryptedValueBytes := inJsonObject.Path(config.GetEncryptedValueFieldName()).Data().(string)
	decodedEncryptedValue := utils.DecodeData(encryptedValueBytes, config.GetFieldValueEncoding())

	iv := inJsonObject.Path("iv").Data().(string)
	decodedIv := utils.DecodeData(iv, config.GetFieldValueEncoding())

	secretKey := inJsonObject.Path("encryptedKey").Data().(string)
	decodedKey := utils.DecodeData(secretKey, config.GetFieldValueEncoding())

	var decryptedKey []byte
	if config.GetOaepPaddingDigestAlgorithm() == "SHA256" {
		decryptedKey, _ = rsa.DecryptOAEP(sha256.New(), rand.Reader, config.GetDecryptionKey(), decodedKey, nil)
	} else {
		decryptedKey, _ = rsa.DecryptOAEP(sha512.New(), rand.Reader, config.GetDecryptionKey(), decodedKey, nil)
	}

	decryptedValueBytes, _ := aes_encryption.AesCbcDecrypt(decodedEncryptedValue, decryptedKey, decodedIv, nil)

	jsonDecryptedPayload, _ := gabs.ParseJSON(decryptedValueBytes)
	if jsonPathOut == "$" {
		jsonPayload = jsonDecryptedPayload
	} else {
		jsonPayload.DeleteP(jsonPathIn)
		jsonPayload.SetP(jsonDecryptedPayload, jsonPathOut)
	}
	return jsonPayload
}
