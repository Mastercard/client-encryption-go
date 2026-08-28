package jwe

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"strings"

	"github.com/mastercard/client-encryption-go/aes_encryption"
	"github.com/mastercard/client-encryption-go/utils"
)

const (
	A128CBC_HS256 = "A128CBC-HS256"
	A256GCM       = "A256GCM"
	A128GCM       = "A128GCM"
	A192GCM       = "A192GCM"
)

type JWEObject struct {
	JoseHeader   *JOSEHeader
	Aad          string
	EncryptedKey string
	Iv           string
	CipherText   string
	AuthTag      string
}

func ParseJWEObject(encryptedPayload string) (*JWEObject, error) {
	payload := strings.Trim(encryptedPayload, " ")
	splitPayload := strings.Split(payload, ".")
	rawHeader, encryptedKey, iv, cipherText, authTag := splitPayload[0], splitPayload[1], splitPayload[2], splitPayload[3], splitPayload[4]

	joseHeader, err := ParseJOSEHeader(rawHeader)
	if err != nil {
		return nil, err
	}

	jweObject := &JWEObject{
		JoseHeader:   joseHeader,
		Aad:          rawHeader,
		EncryptedKey: encryptedKey,
		Iv:           iv,
		CipherText:   cipherText,
		AuthTag:      authTag,
	}

	return jweObject, nil
}

func (jweObject JWEObject) Decrypt(config JWEConfig) (string, error) {
	// rsa decrypt the encryptedKey
	encryptedKey := utils.Base64UrlDecode(jweObject.EncryptedKey)
	cek, err := config.decryptionKey.Decrypt(nil, encryptedKey, &rsa.OAEPOptions{Hash: crypto.SHA256})

	if err != nil {
		return "", err
	}
	// // decrypt the payload using the key and return the result
	cipherText := utils.Base64UrlDecode(jweObject.CipherText)
	nonce := utils.Base64UrlDecode(jweObject.Iv)
	authTag := utils.Base64UrlDecode(jweObject.AuthTag)
	aad := []byte(jweObject.Aad)

	switch encryptionMethod := jweObject.JoseHeader.Enc; encryptionMethod {
	case A128GCM:
		plainText, err := aes_encryption.AesGcmDecrypt(cipherText, cek, nonce, authTag, aad)
		if err != nil {
			return "", err
		}
		return string(plainText), nil
	case A192GCM:
		plainText, err := aes_encryption.AesGcmDecrypt(cipherText, cek, nonce, authTag, aad)
		if err != nil {
			return "", err
		}
		return string(plainText), nil
	case A256GCM:
		plainText, err := aes_encryption.AesGcmDecrypt(cipherText, cek, nonce, authTag, aad)
		if err != nil {
			return "", err
		}
		return string(plainText), nil
	case A128CBC_HS256:
		if config.enableAuthTagVerification {
			if err := verifyCbcAuthTag(cek, nonce, cipherText, authTag, aad); err != nil {
				return "", err
			}
		}
		plainText, err := aes_encryption.AesCbcDecrypt(cipherText, cek[16:], nonce, authTag)
		if err != nil {
			return "", err
		}
		return string(plainText), nil

	default:
		return "", errors.New("Encryption method not supported")
	}
}

func verifyCbcAuthTag(cek, nonce, cipherText, authTag, aad []byte) error {
	if len(cek) != 32 {
		return errors.New("invalid cek length for A128CBC-HS256")
	}
	macKeyLen := len(cek) / 2
	macKey := cek[:macKeyLen]

	if len(authTag) != 16 {
		return errors.New("invalid authentication tag length")
	}

	al := make([]byte, 8)
	binary.BigEndian.PutUint64(al, uint64(len(aad)*8))

	mac := hmac.New(sha256.New, macKey)
	mac.Write(aad)
	mac.Write(nonce)
	mac.Write(cipherText)
	mac.Write(al)
	expected := mac.Sum(nil)

	expectedAuthTag := expected[:len(authTag)]
	if subtle.ConstantTimeCompare(authTag, expectedAuthTag) != 1 {
		return errors.New("invalid authentication tag")
	}

	return nil
}

func (jweObject JWEObject) Serialize() string {
	return strings.Join([]string{jweObject.Aad, jweObject.EncryptedKey, jweObject.Iv, jweObject.CipherText, jweObject.AuthTag}, ".")
}

func Encrypt(config JWEConfig, payload string, header JOSEHeader) (string, error) {
	cek := config.cek
	if cek == nil {
		cek = aes_encryption.GenerateCEK(256)
	}
	encryptionKey := config.encryptionKey

	encryptedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, encryptionKey, cek, nil)
	if err != nil {
		return "", err
	}

	iv := config.iv
	if iv == nil {
		iv = aes_encryption.GenerateCEK(96)
	}

	rawHeader, err := header.ToJson()
	if err != nil {
		return "", nil
	}

	aad := utils.Base64UrlEncode(rawHeader)
	cipherText, authTag, err := aes_encryption.AesGcmEncrypt([]byte(payload), cek, iv, []byte(aad))
	jweObject := JWEObject{
		JoseHeader:   &header,
		Aad:          aad,
		EncryptedKey: utils.Base64UrlEncode(encryptedKey),
		Iv:           utils.Base64UrlEncode(iv),
		CipherText:   utils.Base64UrlEncode(cipherText),
		AuthTag:      utils.Base64UrlEncode(authTag),
	}
	return jweObject.Serialize(), nil
}
