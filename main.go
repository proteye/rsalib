package main

import (
	"bytes"
	"fmt"
	rsalib "rsalib/lib"
)

func main() {
	params := rsalib.KeyParams{}
	keyPair, err := rsalib.GenerateKeyPair(&params)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	fmt.Println("RSA key pair =", keyPair.PrivateKey)
	maxLen := keyPair.PublicKey.Size()
	fmt.Println("\nMax text len =", maxLen*8)

	message := []byte("Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello!!!")
	fmt.Println("\nText len =", len(message)*8)

	cipher, err := rsalib.Encrypt(message, keyPair.PublicKey)
	if err != nil {
		fmt.Println(err.Error())
	} else {
		fmt.Println("\ncipher =", cipher)
	}

	plaintext, err := rsalib.Decrypt(cipher, keyPair.PrivateKey)
	if err != nil {
		fmt.Println(err.Error())
	} else {
		fmt.Println("\nplaintext =", string(plaintext))
	}

	message = []byte("Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! OK!!")
	fmt.Println("\nText len =", len(message)*8)

	cipher, _ = rsalib.Encrypt(message, keyPair.PublicKey)
	fmt.Println("\ncipher =", cipher)

	plaintext, _ = rsalib.Decrypt(cipher, keyPair.PrivateKey)
	fmt.Println("\nplaintext =", string(plaintext))
	fmt.Println("\nIs messages equal?", bytes.Equal(message, plaintext))
}
