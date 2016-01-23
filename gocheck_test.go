package crypto

// xlCrypto_go/gocheck.go

import (
	. "gopkg.in/check.v1"
	"testing"
)

func Test(t *testing.T) { TestingT(t) }

type XLSuite struct{}

var _ = Suite(&XLSuite{})

var (
	VERBOSITY = 1
)
