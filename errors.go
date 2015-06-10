package crypto

// xlCrypto_go/errors.go

import (
	e "errors"
)

var (
	//EmptyHash               = e.New("empty hash slice parameter")
	//EmptyPath               = e.New("empty path parameter")
	EmptyTitle              = e.New("empty title parameter")
	ExhaustedStringArray = e.New("exhausted string array")
	ImpossibleBlockSize     = e.New("impossible block size")
	IncorrectPKCS7Padding   = e.New("incorrectly padded data")
	MissingContentStart     = e.New("missing CONTENT START line")
	NilData                 = e.New("nil data argument")
	NilPrivateKey           = e.New("nil private key parameter")
	NilPublicKey            = e.New("nil public key parameter")
	NotAnRSAPrivateKey      = e.New("Not an RSA private key")
	NotImplemented          = e.New("not implemented")
	NotAnRSAPublicKey       = e.New("Not an RSA public key")
	PemEncodeDecodeFailure  = e.New("Pem encode/decode failure")
	X509ParseOrMarshalError = e.New("X509 parse/marshal error")
)
