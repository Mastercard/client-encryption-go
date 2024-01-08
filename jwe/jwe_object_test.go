package jwe_test

import (
	"testing"

	"github.com/Duong2903/client-encryption-go/jwe"
	"github.com/Duong2903/client-encryption-go/utils"
	"github.com/stretchr/testify/assert"
)

const (
	encryptedPayload256Gcm = "eyJraWQiOiI3NjFiMDAzYzFlYWRlM2E1NDkwZTUwMDBkMzc4ODdiYWE1ZTZlYzBlMjI2YzA3NzA2ZTU5OTQ1MWZjMDMyYTc5IiwiY3R5IjoiYXBwbGljYXRpb25cL2pzb24iLCJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.8c6vxeZOUBS8A9SXYUSrRnfl1ht9xxciB7TAEv84etZhQQ2civQKso-htpa2DWFBSUm-UYlxb6XtXNXZxuWu-A0WXjwi1K5ZAACc8KUoYnqPldEtC9Q2bhbQgc_qZF_GxeKrOZfuXc9oi45xfVysF_db4RZ6VkLvY2YpPeDGEMX_nLEjzqKaDz_2m0Ae_nknr0p_Nu0m5UJgMzZGR4Sk1DJWa9x-WJLEyo4w_nRDThOjHJshOHaOU6qR5rdEAZr_dwqnTHrjX9Qm9N9gflPGMaJNVa4mvpsjz6LJzjaW3nJ2yCoirbaeJyCrful6cCiwMWMaDMuiBDPKa2ovVTy0Sw.w0Nkjxl0T9HHNu4R.suRZaYu6Ui05Z3-vsw.akknMr3Dl4L0VVTGPUszcA"
	encryptedPayload128Gcm = "eyJlbmMiOiJBMTI4R0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.WtvYljbsjdEv-Ttxx1p6PgyIrOsLpj1FMF9NQNhJUAHlKchAo5QImgEgIdgJE7HC2KfpNcHiQVqKKZq_y201FVzpicDkNzlPJr5kIH4Lq-oC5iP0agWeou9yK5vIxFRP__F_B8HSuojBJ3gDYT_KdYffUIHkm_UysNj4PW2RIRlafJ6RKYanVzk74EoKZRG7MIr3pTU6LIkeQUW41qYG8hz6DbGBOh79Nkmq7Oceg0ZwCn1_MruerP-b15SGFkuvOshStT5JJp7OOq82gNAOkMl4fylEj2-vADjP7VSK8GlqrA7u9Tn-a4Q28oy0GOKr1Z-HJgn_CElknwkUTYsWbg.PKl6_kvZ4_4MjmjW.AH6pGFkn7J49hBQcwg.zdyD73TcuveImOy4CRnVpw"
	encryptedPayload192Gcm = "eyJlbmMiOiJBMTkyR0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.FWC8PVaZoR2TRKwKO4syhSJReezVIvtkxU_yKh4qODNvlVr8t8ttvySJ-AjM8xdI6vNyIg9jBMWASG4cE49jT9FYuQ72fP4R-Td4vX8wpB8GonQj40yLqZyfRLDrMgPR20RcQDW2ThzLXsgI55B5l5fpwQ9Nhmx8irGifrFWOcJ_k1dUSBdlsHsYxkjRKMENu5x4H6h12gGZ21aZSPtwAj9msMYnKLdiUbdGmGG_P8a6gPzc9ih20McxZk8fHzXKujjukr_1p5OO4o1N4d3qa-YI8Sns2fPtf7xPHnwi1wipmCC6ThFLU80r3173RXcpyZkF8Y3UacOS9y1f8eUfVQ.JRE7kZLN4Im1Rtdb.eW_lJ-U330n0QHqZnQ._r5xYVvMCrvICwLz4chjdw"
	encryptedPayloadCbc    = "eyJraWQiOiI3NjFiMDAzYzFlYWRlM2E1NDkwZTUwMDBkMzc4ODdiYWE1ZTZlYzBlMjI2YzA3NzA2ZTU5OTQ1MWZjMDMyYTc5IiwiY3R5IjoiYXBwbGljYXRpb25cL2pzb24iLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.5bsamlChk0HR3Nqg2UPJ2Fw4Y0MvC2pwWzNv84jYGkOXyqp1iwQSgETGaplIa7JyLg1ZWOqwNHEx3N7gsN4nzwAnVgz0eta6SsoQUE9YQ-5jek0COslUkoqIQjlQYJnYur7pqttDibj87fcw13G2agle5fL99j1QgFPjNPYqH88DMv481XGFa8O3VfJhW93m73KD2gvE5GasOPOkFK9wjKXc9lMGSgSArp3Awbc_oS2Cho_SbsvuEQwkhnQc2JKT3IaSWu8yK7edNGwD6OZJLhMJzWJlY30dUt2Eqe1r6kMT0IDRl7jHJnVIr2Qpe56CyeZ9V0aC5RH1mI5dYk4kHg.yI0CS3NdBrz9CCW2jwBSDw.6zr2pOSmAGdlJG0gbH53Eg.UFgf3-P9UjgMocEu7QA_vQ"
)

func TestJWEObject(t *testing.T) {
	joseHeader := jwe.JOSEHeader{
		Alg: "RSA-OAEP-256",
		Enc: "A256GCM",
		Cty: "application/json",
		Kid: "123",
	}
	jweObject := jwe.JWEObject{&joseHeader, "aad", "secret-key", "iv", "cipherText", "authTag"}
	assert.Equal(t, jweObject.JoseHeader, &joseHeader)
	assert.Equal(t, jweObject.Aad, "aad")
	assert.Equal(t, jweObject.EncryptedKey, "secret-key")
	assert.Equal(t, jweObject.Iv, "iv")
	assert.Equal(t, jweObject.CipherText, "cipherText")
	assert.Equal(t, jweObject.AuthTag, "authTag")
}

func TestParseJWEObject(t *testing.T) {
	jweObject, err := jwe.ParseJWEObject(encryptedPayload256Gcm)
	joseHeader := jweObject.JoseHeader

	assert.Nil(t, err)
	assert.Equal(t, joseHeader.Enc, "A256GCM")
	assert.Equal(t, joseHeader.Alg, "RSA-OAEP-256")
	assert.Equal(t, joseHeader.Kid, "761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79")
	assert.Equal(t, joseHeader.Cty, "application/json")
}

func TestDecrypt_ShouldReturnDecryptedPayload_WhenPayloadIs256GcmEncrypted(t *testing.T) {
	jweObject, err := jwe.ParseJWEObject(encryptedPayload256Gcm)
	assert.Nil(t, err)
	decryptionKeyPath := "../testdata/keys/pkcs8/test_key_pkcs8-2048.der"
	certificatePath := "../testdata/certificates/test_certificate-2048.der"

	decryptionKey, err := utils.LoadUnencryptedDecryptionKey(decryptionKeyPath)
	assert.Nil(t, err)
	certificate, err := utils.LoadEncryptionCertificate(certificatePath)
	assert.Nil(t, err)

	cb := jwe.NewJWEConfigBuilder()
	jweConfig := cb.WithDecryptionKey(decryptionKey).
		WithCertificate(certificate).
		Build()

	decryptedPayload, err := jweObject.Decrypt(*jweConfig)
	assert.Nil(t, err)
	assert.Equal(t, "{\"foo\":\"bar\"}", decryptedPayload)
}

func TestDecrypt_ShouldReturnDecryptedPayload_WhenPayloadIs128GcmEncrypted(t *testing.T) {
	jweObject, err := jwe.ParseJWEObject(encryptedPayload128Gcm)
	assert.Nil(t, err)
	decryptionKeyPath := "../testdata/keys/pkcs8/test_key_pkcs8-2048.der"
	certificatePath := "../testdata/certificates/test_certificate-2048.der"

	decryptionKey, err := utils.LoadUnencryptedDecryptionKey(decryptionKeyPath)
	assert.Nil(t, err)
	certificate, err := utils.LoadEncryptionCertificate(certificatePath)
	assert.Nil(t, err)

	cb := jwe.NewJWEConfigBuilder()
	jweConfig := cb.WithDecryptionKey(decryptionKey).
		WithCertificate(certificate).
		Build()

	decryptedPayload, err := jweObject.Decrypt(*jweConfig)
	assert.Nil(t, err)
	assert.Equal(t, "{\"foo\":\"bar\"}", decryptedPayload)
}

func TestDecrypt_ShouldReturnDecryptedPayload_WhenPayloadIs192GcmEncrypted(t *testing.T) {
	jweObject, err := jwe.ParseJWEObject(encryptedPayload192Gcm)
	assert.Nil(t, err)
	decryptionKeyPath := "../testdata/keys/pkcs8/test_key_pkcs8-2048.der"
	certificatePath := "../testdata/certificates/test_certificate-2048.der"

	decryptionKey, err := utils.LoadUnencryptedDecryptionKey(decryptionKeyPath)
	assert.Nil(t, err)
	certificate, err := utils.LoadEncryptionCertificate(certificatePath)
	assert.Nil(t, err)

	cb := jwe.NewJWEConfigBuilder()
	jweConfig := cb.WithDecryptionKey(decryptionKey).
		WithCertificate(certificate).
		Build()

	decryptedPayload, err := jweObject.Decrypt(*jweConfig)
	assert.Nil(t, err)
	assert.Equal(t, "{\"foo\":\"bar\"}", decryptedPayload)
}

func TestJWEObjectSerialize(t *testing.T) {
	jweObject, err := jwe.ParseJWEObject(encryptedPayload256Gcm)
	assert.Nil(t, err)
	serializedData := jweObject.Serialize()
	assert.Equal(t, encryptedPayload256Gcm, serializedData)
}

func TestDecrypt_ShouldReturnDecryptedPayload_WhenPayloadIsCbcEncrypted(t *testing.T) {
	jweObject, err := jwe.ParseJWEObject(encryptedPayloadCbc)
	assert.Nil(t, err)
	decryptionKeyPath := "../testdata/keys/pkcs8/test_key_pkcs8-2048.der"
	certificatePath := "../testdata/certificates/test_certificate-2048.der"

	decryptionKey, err := utils.LoadUnencryptedDecryptionKey(decryptionKeyPath)
	assert.Nil(t, err)
	certificate, err := utils.LoadEncryptionCertificate(certificatePath)
	assert.Nil(t, err)

	cb := jwe.NewJWEConfigBuilder()
	jweConfig := cb.WithDecryptionKey(decryptionKey).
		WithCertificate(certificate).
		Build()

	decryptedPayload, err := jweObject.Decrypt(*jweConfig)
	assert.Nil(t, err)
	assert.Equal(t, "bar", decryptedPayload)
}
