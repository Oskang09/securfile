package securfile

type Encryptor struct {
	cipherKey string
	authKey   string
}

func NewEncryptor(cipherKey string) *Encryptor {
	encryptor := new(Encryptor)
	encryptor.cipherKey = cipherKey
	return encryptor
}

func (enc *Encryptor) WithKey(key string) {
	enc.authKey = key
}

func (enc *Encryptor) MarshalString(cipherValue string) (string, error) {
	return DecryptString(cipherValue, enc.cipherKey, enc.authKey)
}

func (enc *Encryptor) MarshalBytes(cipherValue []byte) (string, error) {
	return DecryptBytes(cipherValue, enc.cipherKey, enc.authKey)
}
