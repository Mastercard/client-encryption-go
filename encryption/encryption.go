package encryption

import (
	"github.com/Jeffail/gabs/v2"
	"github.com/mastercard/client-encryption-go/jwe"
	"strings"
)

func EncryptPayload(payload string, config jwe.JWEConfig) string {
	jsonPayload, _ := gabs.ParseJSON([]byte(payload))
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

	payload, err := jwe.Encrypt(config, jsonPayload.Path(jsonPathIn).String(), joseHeader)
	if err != nil {
		panic(err)
	}

	if jsonPathIn == "$" {
		jsonPayload = gabs.New()
	} else {
		jsonPayload.DeleteP(jsonPathIn)
	}

	jsonPathOut = jsonPathOut + "." + config.GetEncryptedValueFieldName()

	jsonPayload.Set(payload, strings.Split(jsonPathOut, ".")...)

	return jsonPayload
}

func decryptPayloadPath(jsonPayload *gabs.Container, jsonPathIn string, jsonPathOut string, config jwe.JWEConfig) *gabs.Container {
	inJsonObject := jsonPayload.Path(jsonPathIn).Data().(string)
	jweObject, err := jwe.ParseJWEObject(inJsonObject)
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
		jsonPayload.DeleteP(jsonPathIn)
		jsonPayload.Set(jsonDecryptedPayload, strings.Split(jsonPathOut, ".")...)
	}

	return jsonPayload
}
