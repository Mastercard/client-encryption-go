package mastercard_encryption

import (
	"github.com/Jeffail/gabs/v2"
	"github.com/mastercard/client-encryption-go/aes_encryption"
	"github.com/mastercard/client-encryption-go/field_level_encryption"
	"github.com/mastercard/client-encryption-go/utils"
)

func EncryptPayload(payload string, config *field_level_encryption.FieldLevelEncryptionConfig, params *field_level_encryption.FieldLevelEncryptionParams) string {
	jsonPayload, _ := gabs.ParseJSON([]byte(payload))
	for jsonPathIn, jsonPathOut := range config.GetEncryptionPaths() {
		jsonPayload = encryptPayloadPath(jsonPayload, jsonPathIn, jsonPathOut, config, params)
	}
	return jsonPayload.String()
}

func encryptPayloadPath(jsonPayload *gabs.Container, jsonPathIn string, jsonPathOut string,
	config *field_level_encryption.FieldLevelEncryptionConfig, params *field_level_encryption.FieldLevelEncryptionParams) *gabs.Container {
	if params == nil {
		params = field_level_encryption.Generate(config)
	}
	encryptedValueBytes, _, _ := aes_encryption.AesCbcEncrypt(jsonPayload.Bytes(), params.SecretKey, params.IvParameterSpec, nil)
	payload := utils.HexUrlEncode(encryptedValueBytes)

	if jsonPathIn == "$" {
		jsonPayload = gabs.New()
	} else {
		jsonPayload.DeleteP(jsonPathIn)
	}
	if !utils.IsNullOrEmpty(config.GetEncryptedValueFieldName()) {
		jsonPayload.Set(payload, config.GetEncryptedValueFieldName())
	}

	if !utils.IsNullOrEmpty(config.GetIvFieldName()) {
		jsonPayload.Set(params.IvValue, config.GetIvFieldName())
	}

	if !utils.IsNullOrEmpty(config.GetEncryptedKeyFieldName()) {
		jsonPayload.Set(params.EncryptedKeyValue, config.GetEncryptedKeyFieldName())
	}

	if !utils.IsNullOrEmpty(config.GetEncryptionKeyFingerprintFieldName()) {
		jsonPayload.Set(config.GetEncryptionKeyFingerprint(), config.GetEncryptionKeyFingerprintFieldName())
	}

	if !utils.IsNullOrEmpty(config.GetOaepPaddingDigestAlgorithmFieldName()) {
		jsonPayload.Set(params.OaepPaddingDigestAlgorithmValue, config.GetOaepPaddingDigestAlgorithmFieldName())
	}
	return jsonPayload
}
