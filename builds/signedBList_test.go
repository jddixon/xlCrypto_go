package builds

// xlCrypto_go/builds/buildList_test.go

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	xr "github.com/jddixon/rnglib_go"
	xc "github.com/jddixon/xlCrypto_go"
	. "launchpad.net/gocheck"
	"strings"
)

var _ = fmt.Print

const (
	docTitle = "document 1"
	docTime  = "2004-11-18 20:03:34"
	// a folded RSA public key
	docPK1    = "rsa AL0zGtdGkuJdH1vd4TaUMmRvdEBepnGfAbvZXPkdsVq367VUevbfzNL4W6u+Ks8+BksZzZPc"
	docPK2    = "yLJsnDZr7mE/rHSwQ7la1HlSWwNDlhQtCnKTlSoqffVhofhtak/SqBOJVLkWrouaK60uCiZV0Hw"
	docPK3    = "YTM6Pqo8sqYinA3W8mvK2tsW/ 65537"
	docPubKey = docPK1 + FOLD + docPK2 + FOLD + docPK3

	docEncodedSig = "tIQJ+7Y27eIyQCb3esTgU/AdBfPDAGEOhU/KShAo5N5dfxtjkH04N5IwvyftEJd5jM0kHB1LD1TtavoxZ0gx4eADizHcDjEpZOiO+wUHIcbGsuvLUvZvBttPPBRuRfZgZXkvvSMBX0KIwRVgFqwaRB5gzQyD2skcP2kGFBWrFdM="
	testDoc       = docTitle + CRLF +
		docTime + CRLF +
		docPubKey + CRLF +
		docEncodedSig
)

func (s *XLSuite) TestEmptySignedBList(c *C) {
	var (
		err    error
		myList *SignedBList
		key    *rsa.PrivateKey
		pubKey *rsa.PublicKey
	)
	key, err = rsa.GenerateKey(rand.Reader, 1024)
	c.Assert(err, IsNil)
	pubKey = &key.PublicKey
	myList, err = NewSignedBList("document 1", pubKey)
	c.Assert(err, IsNil)
	c.Assert(myList, NotNil)
	c.Assert(myList.Size(), Equals, uint(0))
	c.Assert(myList.IsSigned(), Equals, false)

	myList.Sign(key)
	c.Assert(myList.IsSigned(), Equals, true)
	c.Assert(myList.Verify(), IsNil)

	err = myList.Sign(key)
	c.Assert(err, Equals, ListAlreadySigned)
}

func (s *XLSuite) TestGeneratedSignedBList(c *C) {
	var (
		err    error
		myList *SignedBList
		key    *rsa.PrivateKey
		pubKey *rsa.PublicKey
	)
	rng := xr.MakeSimpleRNG()

	hash0 := make([]byte, xc.SHA1_LEN)
	hash1 := make([]byte, xc.SHA1_LEN)
	hash2 := make([]byte, xc.SHA1_LEN)
	hash3 := make([]byte, xc.SHA1_LEN)
	rng.NextBytes(hash0)
	rng.NextBytes(hash1)
	rng.NextBytes(hash2)
	rng.NextBytes(hash3)

	key, err = rsa.GenerateKey(rand.Reader, 1024)
	c.Assert(err, IsNil)
	c.Assert(key, NotNil)
	pubKey = &key.PublicKey
	c.Assert(pubKey, NotNil)
	myList, err = NewSignedBList("document 1", pubKey)
	c.Assert(err, IsNil)
	c.Assert(myList, NotNil)
	c.Assert(myList.Size(), Equals, uint(0))
	c.Assert(myList.IsSigned(), Equals, false)

	// XXX NOTE WE CAN ADD DUPLICATE OR CONFLICTING ITEMS !! XXX
	err = myList.Add(hash0, "fileForHash0")
	c.Assert(err, IsNil)
	c.Assert(myList.Size(), Equals, uint(1))

	err = myList.Add(hash1, "fileForHash1")
	c.Assert(err, IsNil)
	c.Assert(myList.Size(), Equals, uint(2))

	err = myList.Add(hash2, "fileForHash2")
	c.Assert(err, IsNil)
	c.Assert(myList.Size(), Equals, uint(3))

	err = myList.Add(hash3, "fileForHash3")
	c.Assert(err, IsNil)
	c.Assert(myList.Size(), Equals, uint(4))

	// check (arbitrarily) second content line
	expected1 := base64.StdEncoding.EncodeToString(hash1) + " fileForHash1"
	actual1, err := myList.Get(1)
	c.Assert(err, IsNil)
	c.Assert(expected1, Equals, actual1)
	err = myList.Sign(key)
	c.Assert(err, IsNil)
	c.Assert(myList.IsSigned(), Equals, true)
	err = myList.Verify()
	c.Assert(err, IsNil)
	myDoc, err := myList.String()
	c.Assert(err, IsNil)

	// DEBUG
	fmt.Printf("MY_DOC:\n%s", myDoc)
	// END

	reader := strings.NewReader(myDoc)
	list2, err := ParseSignedBList(reader)
	c.Assert(err, IsNil)
	c.Assert(list2, NotNil)
	c.Assert(list2.Size(), Equals, uint(4))
	c.Assert(list2.IsSigned(), Equals, true) // FAILS

	str, err := list2.String()
	c.Assert(err, IsNil)
	c.Assert(str, Equals, myDoc)
	c.Assert(list2.Verify(), IsNil)

	// test item gets - sloppy naming, so can't loop :-(
	b := myList.GetItemHash(0)
	c.Assert(bytes.Equal(b, hash0), Equals, true)
	c.Assert(myList.GetPath(0), Equals, "fileForHash0")

	b = myList.GetItemHash(1)
	c.Assert(bytes.Equal(b, hash1), Equals, true)
	c.Assert(myList.GetPath(1), Equals, "fileForHash1")

}
