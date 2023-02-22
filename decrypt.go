package securfile

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
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
