package builds

// xlCrypto_go/builds/item.go

import (
	"encoding/base64"
)

/**
 * Items in the build list: the hash of a file (a content hash
 * or the hash of a SignedList) and the path of the file,
 * including its name.
 */

type Item struct {
	EHash []byte
	Path  string
}

func NewItem(hash []byte, path string) (i *Item, err error) {

	if len(hash) == 0 {
		err = EmptyHash
	} else if len(path) == 0 {
		err = EmptyPath
	} else {
		i = &Item{
			EHash: hash,
			Path:  path,
		}
	}
	return
}

func (i *Item) GetHash() []byte {
	return i.EHash
}

func (i *Item) GetPath() string {
	return i.Path
}

// SERIALIZATION ////////////////////////////////////////////////////

func (i *Item) String() string {
	return base64.StdEncoding.EncodeToString(i.EHash) + " " + i.Path
}
