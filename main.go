package main

import (
	"fmt"
	rsalib "rsalib/lib"
)

func main() {
	params := rsalib.RsaKeyParams{}
	keyPair, err := rsalib.GenerateKeyPair(params)
	if err != nil {
		println(err.Error())
	}

	fmt.Println("keyPair =", keyPair.PrivateKey)
	maxLen := keyPair.PublicKey.Size()

	fmt.Println("Max text len =", maxLen)
	text := []byte("Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello, World! Hello!!!")

	fmt.Println("Text len =", len(text))
	cipher, _ := rsalib.Encrypt(text, keyPair.PublicKey)
	fmt.Println("cipher =", cipher)

	plaintext, _ := rsalib.Decrypt(cipher, keyPair.PrivateKey)
	fmt.Println("plaintext =", string(plaintext))

	fmt.Println("Text len =", maxLen)
	cipher, _ = rsalib.Encrypt(text[:maxLen], keyPair.PublicKey)
	fmt.Println("cipher =", cipher)

	plaintext, _ = rsalib.Decrypt(cipher, keyPair.PrivateKey)
	fmt.Println("plaintext =", string(plaintext))
}
