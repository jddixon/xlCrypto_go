package crypto

// xlCrypto_go/itemI.go

type ItemI interface {
	GetHash() []byte
	GetPath() string
}
