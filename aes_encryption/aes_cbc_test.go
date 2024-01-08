package aes_encryption_test

import (
	"testing"

	"github.com/Duong2903/client-encryption-go/aes_encryption"
	"github.com/stretchr/testify/assert"
)

func TestCbcEncryption(t *testing.T) {
	expectedCipherText := []byte{40, 57, 83, 181, 119, 33, 133, 148, 198, 185, 243, 24, 152, 230, 6,
		75, 129, 223, 127, 19, 210, 82, 183, 230, 168, 33, 215, 104, 143,
		112, 56, 102}

	expectedAuthTag := []byte{46, 17, 244, 190, 4, 95, 98, 3, 231, 0, 115, 157, 242, 203, 100,
		191}

	cek := []byte{107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156,
		44, 207}

	iv := []byte{3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111, 116, 104,
		101}

	aad := []byte{101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 83, 85, 48, 69,
		120, 88, 122, 85, 105, 76, 67, 74, 108, 98, 109, 77, 105, 79, 105,
		74, 66, 77, 84, 73, 52, 81, 48, 74, 68, 76, 85, 104, 84, 77, 106, 85,
		50, 73, 110, 48}

	plainText := []byte("Live long and prosper.")

	cipherText, authTag, err := aes_encryption.AesCbcEncrypt(plainText, cek, iv, aad)

	assert.Nil(t, err)
	assert.Equal(t, expectedCipherText, cipherText)
	assert.Equal(t, expectedAuthTag, authTag)
}

func TestCbcDecryption(t *testing.T) {
	cek := []byte{107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156,
		44, 207}

	iv := []byte{3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111, 116, 104,
		101}

	aad := []byte{101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 83, 85, 48, 69,
		120, 88, 122, 85, 105, 76, 67, 74, 108, 98, 109, 77, 105, 79, 105,
		74, 66, 77, 84, 73, 52, 81, 48, 74, 68, 76, 85, 104, 84, 77, 106, 85,
		50, 73, 110, 48}

	plainText := []byte("Live long and prosper.")

	cipherText, _, err := aes_encryption.AesCbcEncrypt(plainText, cek, iv, aad)

	assert.Nil(t, err)

	decryptedText, err := aes_encryption.AesCbcDecrypt(cipherText, cek, iv, nil)
	assert.Nil(t, err)
	assert.Equal(t, plainText, decryptedText)
}
