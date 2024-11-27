package securfile

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
)

func encrypt(data string, cipherKey string, authKey string) (string, error) {
	block, err := aes.NewCipher([]byte(cipherKey))
	if err != nil {
		return "", err
	}

	nonceKey := []byte(randomString(12))
	aesgcm, err := cipher.NewGCMWithNonceSize(block, 12)
	if err != nil {
		return "", err
	}

	encrypted := aesgcm.Seal(nil, nonceKey, []byte(data), []byte(authKey))
	return string(nonceKey) + "," + base64.StdEncoding.EncodeToString(encrypted), nil
}

func EncryptString(value string, cipherKey string, authKey string) (string, error) {
	return encrypt(value, cipherKey, authKey)
}

func EncryptBytes(cipherBytes []byte, cipherKey string, authKey string) (string, error) {
	return EncryptString(string(cipherBytes), cipherKey, authKey)
}
