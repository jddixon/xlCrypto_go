package filters

// xlCrypto_go/filters/gocheck.go

import (
	. "gopkg.in/check.v1"
	"testing"
)

func Test(t *testing.T) { TestingT(t) }

type XLSuite struct{}

var _ = Suite(&XLSuite{})

const VERBOSITY = 1
