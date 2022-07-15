package utils

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"golang.org/x/crypto/pkcs12"
	"io/ioutil"
	"os"
)

// Load certificate in both pem and der format
func LoadEncryptionCertificate(certificatePath string) (*x509.Certificate, error) {
	data, err := readFile(certificatePath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block != nil {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		return cert, nil
	}
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

// LoadDecryptionKey from an Unencrypted Key File
func LoadDecryptionKey(filePath, password string) (*rsa.PrivateKey, error) {
	// read the file content
	privateKeyData, err := readFile(filePath)
	if err != nil {
		return nil, err
	}

	// decode file content to privateKey
	privateKey, _, err := pkcs12.Decode(privateKeyData, password)
	if err != nil {
		return nil, err
	}

	return privateKey.(*rsa.PrivateKey), nil
}

// Load decryption key
func LoadUnencryptedDecryptionKey(keyFilePath string) (*rsa.PrivateKey, error) {
	data, _ := readFile(keyFilePath)
	block, _ := pem.Decode(data)
	if block != nil {
		if block.Type == "PRIVATE KEY" {
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			return key.(*rsa.PrivateKey), nil
		} else if block.Type == "RSA PRIVATE KEY" {
			key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			return key, nil
		}
	}
	key, err := x509.ParsePKCS8PrivateKey(data)
	if err != nil {
		return nil, err
	}
	return key.(*rsa.PrivateKey), nil
}

// Read File
func readFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return ioutil.ReadAll(file)
}
