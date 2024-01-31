package encryption

import (
	"github.com/Jeffail/gabs/v2"
	"github.com/mastercard/client-encryption-go/jwe"
	"strings"
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
	var payloadPath *gabs.Container
	if jsonPathIn == "$" {
		payloadPath = jsonPayload
	} else {
		if jsonPathIn[0] == '$' {
			jsonPathIn = jsonPathIn[2:]
		}
		payloadPath = jsonPayload.Path(jsonPathIn)
	}
	payload, err := jwe.Encrypt(config, payloadPath.String(), joseHeader)
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
		if jsonPathOut[0] == '$' {
			jsonPathOut = jsonPathOut[2:]
		}
		jsonPayload.SetP(payload, jsonPathOut+"."+config.GetEncryptedValueFieldName())
	}
	return jsonPayload
}

func decryptPayloadPath(jsonPayload *gabs.Container, jsonPathIn string, jsonPathOut string, config jwe.JWEConfig) *gabs.Container {
	var inJsonObject string
	if jsonPathIn == "$" {
		inJsonObject = jsonPayload.
			Children()[0].
			Data().(string)
	} else {
		if jsonPathIn[0] == '$' {
			jsonPathIn = jsonPathIn[2:]
		}
		inJsonObject = jsonPayload.Path(jsonPathIn).
			Data().(string)
	}
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
		if jsonPathOut[0] == '$' {
			jsonPathOut = jsonPathOut[2:]
		}
		jsonPayload.DeleteP(getParent(jsonPathIn))
		jsonPayload.SetP(jsonDecryptedPayload, jsonPathOut)
	}
	return jsonPayload
}

func getParent(path string) string {
	keys := strings.Split(path, ".")
	parent := keys[:len(keys)-1]
	return strings.Join(parent, ".")
}
