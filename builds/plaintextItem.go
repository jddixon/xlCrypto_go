package builds

// xlCrypto_go/plaintextItem.go

import (
	"encoding/base64"
	xc "github.com/jddixon/xlCrypto_go"
)

/**
 * Items in the build list: the hash of a file (a content hash
 * or the hash of a SignedList) and the path of the file,
 * including its name.
 */

type PlaintextItem struct {
	EHash []byte
	Path  string
}

func NewPlaintextItem(hash []byte, path string) (i *PlaintextItem, err error) {

	if len(hash) == 0 {
		err = xc.EmptyHash
	} else if len(path) == 0 {
		err = xc.EmptyPath
	} else {
		i = &PlaintextItem{
			EHash: hash,
			Path:  path,
		}
	}
	return
}

func (i *PlaintextItem) GetHash() []byte {
	return i.EHash
}

func (i *PlaintextItem) GetPath() string {
	return i.Path
}

// SERIALIZATION ////////////////////////////////////////////////////

func (i *PlaintextItem) String() string {
	return base64.StdEncoding.EncodeToString(i.EHash) + " " + i.Path
}
