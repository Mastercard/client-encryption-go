package encryption

import (
	"github.com/Jeffail/gabs/v2"
	"github.com/mastercard/client-encryption-go/jwe"
	"github.com/mastercard/client-encryption-go/utils"
)

func EncryptPayload(payload string, config jwe.JWEConfig) string {
	jsonPayload, err := gabs.ParseJSON([]byte(payload))
	if err != nil {
		panic(err)
	}
	for jsonPathIn, jsonPathOut := range config.GetEncryptionPaths() {
		jsonPayload = encryptPayloadPath(jsonPayload, jsonPathIn, jsonPathOut, config)
	}
	return jsonPayload.String()
}

func DecryptPayload(encryptedPayload string, config jwe.JWEConfig) string {
	jsonPayload, _ := gabs.ParseJSON([]byte(encryptedPayload))
	for jsonPathIn, jsonPathOut := range config.GetDecryptionPaths() {
		jsonPayload = decryptPayloadPath(jsonPayload, jsonPathIn, jsonPathOut, config)
	}
	return jsonPayload.String()
}

func encryptPayloadPath(jsonPayload *gabs.Container, jsonPathIn string, jsonPathOut string, config jwe.JWEConfig) *gabs.Container {
	joseHeader := jwe.JOSEHeader{
		Alg: "RSA-OAEP-256",
		Enc: "A256GCM",
		Kid: config.GetEncryptionKeyFingerprint(),
		Cty: "application/json",
	}
	jsonPathIn = utils.RemoveRoot(jsonPathIn)
	jsonPathOut = utils.RemoveRoot(jsonPathOut)
	payloadToEncrypt := utils.GetPayloadToEncrypt(jsonPayload, jsonPathIn)
	payload, err := jwe.Encrypt(config, payloadToEncrypt, joseHeader)
	if err != nil {
		panic(err)
	}
	if jsonPathIn == "$" {
		jsonPayload = gabs.New()
	} else {
		jsonPayload.DeleteP(jsonPathIn)
	}
	if jsonPathOut == "$" {
		jsonPayload.SetP(payload, config.GetEncryptedValueFieldName())
	} else {
		jsonPayload.SetP(payload, jsonPathOut+"."+config.GetEncryptedValueFieldName())
	}
	return jsonPayload
}

func decryptPayloadPath(jsonPayload *gabs.Container, jsonPathIn string, jsonPathOut string, config jwe.JWEConfig) *gabs.Container {
	jsonPathIn = utils.RemoveRoot(jsonPathIn)
	jsonPathOut = utils.RemoveRoot(jsonPathOut)
	encryptedPayload := utils.GetPayloadToDecrypt(jsonPayload, jsonPathIn)
	jweObject, err := jwe.ParseJWEObject(encryptedPayload)
	if err != nil {
		panic(err)
	}
	decryptedPayload, err := jweObject.Decrypt(config)
	if err != nil {
		panic(err)
	}
	jsonDecryptedPayload, err := gabs.ParseJSON([]byte(decryptedPayload))
	if jsonPathOut == "$" {
		jsonPayload = jsonDecryptedPayload
	} else {
		jsonPayload.DeleteP(utils.GetParent(jsonPathIn))
		jsonPayload.SetP(jsonDecryptedPayload, jsonPathOut)
	}
	return jsonPayload
}
