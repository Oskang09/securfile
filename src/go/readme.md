# Securfile

Encrypt your file and decrypt in your application in ease!

**Note:** This encryption & decryption is not a standard, but just a personal practice to encrypt important file which have to stay inside repository. ( while only can decrypt via environment variables )


# Installation

```
go get github.com/Oskang09/securfile
```

# Example & Usage


## Decrypting File

```go
package main

import (
	"os"

	"github.com/Oskang09/securfile"
)

// you can retrieve your key with your own ways instead from env vars
var SecurFileKey = os.Getenv("SECURFILE_KEY")

func main() {
    file := "some/path/to/your/file"
    pfx, err := securfile.DecryptFile(file, SecurFileKey, "auth_key")
    if err != nil {
        // do error handling when decrypt failed
    }
}
```

## Encrypt & Decrypt String

```go
package main

import (
	"log"
	"os"

	"github.com/Oskang09/securfile"
)

var SecurFileKey = os.Getenv("SECURFILE_KEY")

func main() {
	encrypted, err := securfile.EncryptString("somedata", SecurFileKey, "")
	if err != nil {
		// do error handling failed to encrypt
	}

	data, err := securfile.DecryptString(encrypted, SecurFileKey, "")
	if err != nil {
		// do error handling failed to decrypt
	}

	log.Println(data) // print: somedata
}
```

## Use of Decryptor

```go
package main

import (
	"os"

	"github.com/Oskang09/securfile"
)

var SecurFileKey = os.Getenv("SECURFILE_KEY")

func main() {
	decryptor := securfile.NewDecryptor(SecurFileKey)
	decryptor.WithKey("authkey") // optional, set only if you have auth key

	data, err := decryptor.UnmarshalFile("some/path/to/your/file")
	if err != nil {
		// do error handling failed to decrypt
	}

	data, err = decryptor.UnmarshalString("some_encrypted_cipher_value")
	if err != nil {
		// do error handling failed to decrypt
	}
}
```

## Use of Encryptor

```go
package main

import (
	"os"

	"github.com/Oskang09/securfile"
)

var SecurFileKey = os.Getenv("SECURFILE_KEY")

func main() {
	encrypor := securfile.NewEncryptor(SecurFileKey)
	encrypor.WithKey("authkey") // optional, set only if you have auth key

	data, err := encrypor.MarshalString("some_data_to_encrypt")
	if err != nil {
		// do error handling failed to encrypt
	}
}
```

# Browser Tool ( [Securfile Encrypter](https://securfile.oskadev.com/) )

A dead simple browser tools, mainly for ease your work, don't need to always using code to encrypt the file instead encrypt from browser and able to decrypt it when runtime.

![Screenshot of browser tool](/docs/browser-tool.png)