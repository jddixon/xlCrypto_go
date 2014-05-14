package filters

// xlCrypto_go/filters/gocheck.go

import (
	. "launchpad.net/gocheck"
	"testing"
)

func Test(t *testing.T) { TestingT(t) }

type XLSuite struct{}

var _ = Suite(&XLSuite{})

const VERBOSITY = 1
