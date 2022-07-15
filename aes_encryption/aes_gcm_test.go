package aes_encryption_test

import (
	"testing"

	"github.com/mastercard/client-encryption-go/aes_encryption"
	"github.com/stretchr/testify/assert"
)

func TestAESGCMDecryption(t *testing.T) {
	plainText := []byte("HelloWorld")
	cek := aes_encryption.GenerateCEK(256)
	nonce := aes_encryption.GenerateCEK(96)

	cipherText, authTag, err := aes_encryption.AesGcmEncrypt(plainText, cek, nonce, nil)
	assert.Nil(t, err)

	decryptedPlainText, err := aes_encryption.AesGcmDecrypt(cipherText, cek, nonce, authTag, nil)
	assert.Nil(t, err)
	assert.Equal(t, decryptedPlainText, plainText)
}

func TestAESGCMEncryption(t *testing.T) {
	expectedCipherText := []byte{229, 236, 166, 241, 53, 191, 115, 196, 174, 43, 73, 109, 39, 122,
		233, 96, 140, 206, 120, 52, 51, 237, 48, 11, 190, 219, 186, 80, 111,
		104, 50, 142, 47, 167, 59, 61, 181, 127, 196, 21, 40, 82, 242, 32,
		123, 143, 168, 226, 73, 216, 176, 144, 138, 247, 106, 60, 16, 205,
		160, 109, 64, 63, 192}

	expectedAuthTag := []byte{92, 80, 104, 49, 133, 25, 161, 215, 173, 101, 219, 211, 136, 91,
		210, 145}

	cek := []byte{177, 161, 244, 128, 84, 143, 225, 115, 63, 180, 3, 255, 107, 154,
		212, 246, 138, 7, 110, 91, 112, 46, 34, 105, 47, 130, 203, 46, 122,
		234, 64, 252}

	iv := []byte{227, 197, 117, 252, 2, 219, 233, 68, 180, 225, 77, 219}

	aad := []byte{101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 83, 85, 48, 69,
		116, 84, 48, 70, 70, 85, 67, 73, 115, 73, 109, 86, 117, 89, 121, 73,
		54, 73, 107, 69, 121, 78, 84, 90, 72, 81, 48, 48, 105, 102, 81}

	plainText := []byte("The true sign of intelligence is not knowledge but imagination.")

	cipherText, authTag, err := aes_encryption.AesGcmEncrypt(plainText, cek, iv, aad)

	assert.Nil(t, err)
	assert.Equal(t, expectedCipherText, cipherText)
	assert.Equal(t, expectedAuthTag, authTag)
}
