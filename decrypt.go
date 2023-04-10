package securfile

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"io/ioutil"
	"strings"
)

var (
	ErrInvalidEncryptedValue = errors.New("securfile: invalid encrypted value")
	ErrInvalidNonceValue     = errors.New("securfile: invalid nonce value")
)

func decrypt(cipherValue string, nonceKey string, cipherKey string, authKey string) (string, error) {
	bytes, err := base64.StdEncoding.DecodeString(cipherValue)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher([]byte(cipherKey))
	if err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCMWithNonceSize(block, len(nonceKey))
	if err != nil {
		return "", err
	}

	text, err := aesgcm.Open(nil, []byte(nonceKey), bytes, []byte(authKey))
	if err != nil {
		return "", err
	}

	return string(text), nil
}

func DecryptString(cipherValue string, cipherKey string, authKey string) (string, error) {
	ciphers := strings.Split(cipherValue, ",")
	if len(ciphers) != 2 {
		return "", ErrInvalidEncryptedValue
	}

	return decrypt(ciphers[1], ciphers[0], cipherKey, authKey)
}

func DecryptBytes(cipherBytes []byte, cipherKey string, authKey string) (string, error) {
	return DecryptString(string(cipherBytes), cipherKey, authKey)
}

func DecryptFile(file string, cipherKey string, authKey string) (string, error) {
	bytes, err := ioutil.ReadFile(file)
	if err != nil {
		return "", err
	}
	return DecryptBytes(bytes, cipherKey, authKey)
}
