package mastercard_encryption

import (
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

func encryptPayloadPath(jsonPayload *gabs.Container, jsonPathIn string, jsonPathOut string, config field_level_encryption.FieldLevelEncryptionConfig) *gabs.Container {
	params := field_level_encryption.Generate(config)
	encryptedValueBytes, _, _ := aes_encryption.AesCbcEncrypt(jsonPayload.Bytes(), params.SecretKey, params.IvParameterSpec, nil)
	payload := utils.HexUrlEncode(encryptedValueBytes)

	if jsonPathIn == "$" {
		jsonPayload = gabs.New()
	} else {
		jsonPayload.DeleteP(jsonPathIn)
	}
	jsonPayload.Set(payload, config.GetEncryptedValueFieldName())
	jsonPayload.Set(params.IvValue, config.GetIvFieldName())
	jsonPayload.Set(params.EncryptedKeyValue, config.GetEncryptedKeyFieldName())
	jsonPayload.Set(config.GetEncryptionKeyFingerprint(), config.GetEncryptionKeyFingerprintFieldName())
	jsonPayload.Set(params.OaepPaddingDigestAlgorithmValue, config.GetOaepPaddingDigestAlgorithmFieldName())
	return jsonPayload
}
