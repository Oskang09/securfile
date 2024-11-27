package securfile

type Decryptor struct {
	cipherKey string
	authKey   string
}

func NewDecryptor(cipherKey string) *Decryptor {
	decryptor := new(Decryptor)
	decryptor.cipherKey = cipherKey
	return decryptor
}

func (dec *Decryptor) WithKey(key string) {
	dec.authKey = key
}

func (dec *Decryptor) UnmarshalString(cipherValue string) (string, error) {
	return DecryptString(cipherValue, dec.cipherKey, dec.authKey)
}

func (dec *Decryptor) UnmarshalBytes(cipherValue []byte) (string, error) {
	return DecryptBytes(cipherValue, dec.cipherKey, dec.authKey)
}

func (dec *Decryptor) UnmarshalFile(file string) (string, error) {
	return DecryptFile(file, dec.cipherKey, dec.authKey)
}
