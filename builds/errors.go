package builds

import (
	e "errors"
)

var (
	CantAddToSignedList  = e.New("can't add, list has been signed")
	EmptyContentLine     = e.New("content line empty after trim")
	IllFormedContentLine = e.New("content line not correctly formed")
	ListAlreadySigned    = e.New("list has already been signed")
	ListNotSigned        = e.New("list has not been signed")
	NilPrivateKey        = e.New("private key parameter must not be nil")
	NilPublicKey         = e.New("public key parameter must not be nil")
	NilTitle             = e.New("buildList title may not be empty")
)
