package builds

// xlCrypto_go/builds/itemI.go

type ItemI interface {
	GetHash() []byte
	GetPath() string
}
