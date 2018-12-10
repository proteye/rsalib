package rsalib

import "math/big"

func Encrypt(plaintext []byte, publicKey *PublicKey) ([]byte, error) {
	m := new(big.Int).SetBytes(plaintext)
	e := big.NewInt(int64(publicKey.E))
	c := new(big.Int)
	c.Exp(m, e, publicKey.N)

	return c.Bytes(), nil
}

func Decrypt(cipher []byte, privateKey *PrivateKey) ([]byte, error) {
	c := new(big.Int).SetBytes(cipher)
	m := new(big.Int)
	m.Exp(c, privateKey.D, privateKey.N)

	return m.Bytes(), nil
}
