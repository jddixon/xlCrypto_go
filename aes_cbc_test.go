package crypto

// xlCrypto_go/aes_cbc_test.go

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	xr "github.com/jddixon/rnglib_go"
	. "gopkg.in/check.v1"
)
var _ = fmt.Print

func (s *XLSuite) makeAESIV(rng *xr.PRNG) (iv []byte) {
	iv = make([]byte, aes.BlockSize)
	rng.NextBytes(iv)	
	return
}
func (s *XLSuite) makeAESKey(rng *xr.PRNG) (iv []byte) {
	iv = make([]byte, 2*aes.BlockSize)
	rng.NextBytes(iv)	
	return
}
	
func (s *XLSuite) checkOneMessage(c *C, rng *xr.PRNG, size int) {

	msg := make([]byte, size)
	rng.NextBytes(msg)
	iv := s.makeAESIV(rng)	
	key := s.makeAESKey(rng)

	// padding ------------------------------------------------------
	padded, err := AddPKCS7Padding(msg, aes.BlockSize)
	c.Assert(err, IsNil)
	paddedLen := len(padded)				// it's been padded to block size
	nBlocks := paddedLen/aes.BlockSize
	c.Assert(nBlocks * aes.BlockSize, Equals, paddedLen)

	// encryption ---------------------------------------------------
	cryptoLen := paddedLen
	ciphertext := make([]byte, cryptoLen)
	
	engineA, err := aes.NewCipher(key)			// cipher.Block
	c.Assert(err, IsNil)
	encrypterA := cipher.NewCBCEncrypter(engineA, iv)
	encrypterA.CryptBlocks(ciphertext, padded)	// dest <- src

	// decryption ---------------------------------------------------
	plaintext := make([]byte, paddedLen)
	engineB, err := aes.NewCipher(key)			// cipher.Block
	c.Assert(err, IsNil)
	decrypterB := cipher.NewCBCDecrypter(engineB, iv)
	decrypterB.CryptBlocks(plaintext, ciphertext)	// dest <- src
	c.Assert(bytes.Equal(plaintext,padded), Equals, true)	// FAILS XXX

	// unpadding ----------------------------------------------------
	reply, err := StripPKCS7Padding(plaintext, aes.BlockSize)
	c.Assert(err, IsNil)
	c.Assert(bytes.Equal(reply, msg), Equals, true)
}

// Verify that AES/CBC/PKCS7 works as expected.  In practical use, the
// IV is sent down the communications channel in clear before the padded
// and encrypted message.  The receiver reads the IV and then uses that
// to decrypt the message proper before stripping off the padding.
func (s *XLSuite) TestAESCipher(c *C) {
	rng := xr.MakeSimpleRNG()		// cheap random bits

	REP_COUNT := 4

	for i := 0; i < REP_COUNT; i++ {
		count := rng.Intn(2 * 1024)
		s.checkOneMessage(c, rng, count)
	}

}

