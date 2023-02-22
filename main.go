package securfile

import (
	"errors"
	"io/ioutil"
	"strings"
)

var (
	ErrInvalidEncryptedValue = errors.New("securfile: invalid encrypted value")
	ErrInvalidNonceValue     = errors.New("securfile: invalid nonce value")
)

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
