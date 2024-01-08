package jwe_test

import (
	"testing"

	"github.com/Duong2903/client-encryption-go/jwe"
	"github.com/stretchr/testify/assert"
)

func TestJOSEHeader(t *testing.T) {
	joseHeader := jwe.JOSEHeader{
		Alg: "RSA-OAEP-256",
		Enc: "A256GCM",
		Kid: "123",
		Cty: "application/json",
	}
	assert.Equal(t, joseHeader.Alg, "RSA-OAEP-256")
	assert.Equal(t, joseHeader.Enc, "A256GCM")
	assert.Equal(t, joseHeader.Cty, "application/json")
	assert.Equal(t, joseHeader.Kid, "123")
}

func TestJOSEHeaderToJson(t *testing.T) {
	joseHeader := jwe.JOSEHeader{"RSA-OAEP-256", "A256GCM", "123", "application/json"}
	jsonEncodedHeader, err := joseHeader.ToJson()

	assert.Nil(t, err)
	expected := "{\"alg\":\"RSA-OAEP-256\",\"enc\":\"A256GCM\",\"kid\":\"123\",\"cty\":\"application/json\"}"
	assert.Equal(t, expected, string(jsonEncodedHeader))
}

func TestParseJOSEHeader(t *testing.T) {
	encodedHeader := "eyJraWQiOiI3NjFiMDAzYzFlYWRlM2E1NDkwZTUwMDBkMzc4ODdiYWE1ZTZlYzBlMjI2YzA3NzA2ZTU5OTQ1MWZjMDMyYTc5IiwiY3R5IjoiYXBwbGljYXRpb25cL2pzb24iLCJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0"
	joseHeader, err := jwe.ParseJOSEHeader(encodedHeader)

	assert.Nil(t, err)
	assert.Equal(t, "RSA-OAEP-256", joseHeader.Alg)
	assert.Equal(t, "A256GCM", joseHeader.Enc)
	assert.Equal(t, "application/json", joseHeader.Cty)
	assert.Equal(t, "761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79", joseHeader.Kid)
}
