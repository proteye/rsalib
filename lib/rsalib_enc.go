package rsalib

import (
	"errors"
	"math/big"
)

func Encrypt(plaintext []byte, publicKey *PublicKey) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, errors.New("rsalib: encryption error - message length should not be 0")
	}

	m := new(big.Int).SetBytes(plaintext)
	if m.Cmp(publicKey.N) > 0 {
		return nil, errors.New("rsalib: encryption error - message length is greater than bits")
	}

	e := big.NewInt(int64(publicKey.E))
	c := new(big.Int).Exp(m, e, publicKey.N)

	return c.Bytes(), nil
}

func Decrypt(cipher []byte, privateKey *PrivateKey) ([]byte, error) {
	if len(cipher) == 0 {
		return nil, errors.New("rsalib: decryption error - cipher length should not be 0")
	}

	c := new(big.Int).SetBytes(cipher)
	if c.Cmp(privateKey.N) > 0 {
		return nil, errors.New("rsalib: decryption error - cipher length is greater than bits")
	}

	m := new(big.Int)
	if privateKey.Precomputed.Dp == nil {
		// standard algorithm
		m.Exp(c, privateKey.D, privateKey.N)
	} else {
		// the Chinese remainder algorithm
		mp := new(big.Int).Exp(c, privateKey.Precomputed.Dp, privateKey.P)
		mq := new(big.Int).Exp(c, privateKey.Precomputed.Dq, privateKey.Q)
		// (mp - mq)
		mp.Sub(mp, mq)
		// h = qinv * (mp - mq) (mod p)
		h := new(big.Int).Mul(mp, privateKey.Precomputed.Qinv)
		h.Mod(h, privateKey.P)
		// m = mq + hq
		m.Mul(h, privateKey.Q)
		m.Add(m, mq)
	}

	return m.Bytes(), nil
}
