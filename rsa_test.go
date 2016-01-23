package crypto

// xlCrypto_go/rsa_test.go

import (
	. "gopkg.in/check.v1"
	"math/big"
)

// Fiddling around to see whether gocheck could compare bigInts (answer: no).
func (s *XLSuite) TestUnity(c *C) {
	c.Assert(big.NewInt(1).Int64(), Equals, (*BIG_ONE).Int64())
}
