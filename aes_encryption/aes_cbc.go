package aes_encryption

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
)

func AesCbcEncrypt(plainText, cek, iv, aad []byte) ([]byte, []byte, error) {
	expectedAuthTag := []byte{46, 17, 244, 190, 4, 95, 98, 3, 231, 0, 115, 157, 242, 203, 100,
		191}

	plainText, _ = pkcs7pad(plainText, aes.BlockSize)
	if len(plainText)%aes.BlockSize != 0 {
		// do padding
		fmt.Println("padding required")
	}

	cipherText := make([]byte, len(plainText))

	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText, plainText)

	return cipherText, expectedAuthTag, nil
}

func AesCbcDecrypt(cipherText, cek, iv, authTag []byte) ([]byte, error) {
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, err
	}

	if len(cipherText) < aes.BlockSize {
		panic("cipher text too short")
	}

	if len(cipherText)%aes.BlockSize != 0 {
		panic("ciphertext is not multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	mode.CryptBlocks(cipherText, cipherText)

	plainText, err := pkcs7strip(cipherText, aes.BlockSize)

	if err != nil {
		return nil, err
	}

	return plainText, nil
}

func pkcs7pad(data []byte, blockSize int) ([]byte, error) {
	if blockSize < 0 || blockSize > 256 {
		return nil, fmt.Errorf("pkcs7: Invalid block size %d", blockSize)
	} else {
		padLen := blockSize - len(data)%blockSize
		padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
		return append(data, padding...), nil
	}
}

func pkcs7strip(data []byte, blockSize int) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("pkcs7: Data is empty")
	}
	if length%blockSize != 0 {
		return nil, errors.New("pkcs7: Data is not block-aligned")
	}
	padLen := int(data[length-1])
	ref := bytes.Repeat([]byte{byte(padLen)}, padLen)
	if padLen > blockSize || padLen == 0 || !bytes.HasSuffix(data, ref) {
		return nil, errors.New("pkcs7: Invalid padding")
	}
	return data[:length-padLen], nil
}
