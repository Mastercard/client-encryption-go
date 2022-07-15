package aes_encryption_test

import (
	"testing"

	"github.com/mastercard/client-encryption-go/aes_encryption"
	"github.com/stretchr/testify/assert"
)

func TestGenerateCEK(t *testing.T) {
	cek := aes_encryption.GenerateCEK(256)
	assert.Equal(t, len(cek), 32)

	newCek := aes_encryption.GenerateCEK(256)
	assert.Equal(t, len(newCek), 32)
	assert.NotEqual(t, newCek, cek, "Keys should be random")
}
