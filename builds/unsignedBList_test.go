package builds

// xlCrypto_go/builds/unsignedBList_test.go

import (
	"bytes"
	"encoding/base64"
	"fmt"
	xr "github.com/jddixon/rnglib_go"
	xc "github.com/jddixon/xlCrypto_go"
	xu "github.com/jddixon/xlUtil_go"
	. "launchpad.net/gocheck"
	"strings"
)

var _ = fmt.Print

const (
	uDocTitle = "document 1"
	uDocTime  = "2004-11-18 20:03:34"
)

func (s *XLSuite) TestEmptyUnsignedBList(c *C) {
	var (
		err    error
		myList *UnsignedBList
	)
	myList, err = NewUnsignedBList("document 1")
	c.Assert(err, IsNil)
	c.Assert(myList, NotNil)
	c.Assert(myList.Size(), Equals, uint(0))

	c.Assert(myList.IsHashed(), Equals, false)
	c.Assert(myList.Verify(), Equals, false)

	myList.SetDocHash()
	c.Assert(myList.IsHashed(), Equals, true)
	c.Assert(myList.Verify(), Equals, true)
}

func (s *XLSuite) TestGeneratedUnsignedBList(c *C) {
	var (
		err    error
		myList *UnsignedBList
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

	myList, err = NewUnsignedBList("document 1")
	c.Assert(err, IsNil)
	c.Assert(myList, NotNil)
	c.Assert(myList.Size(), Equals, uint(0))
	c.Assert(myList.IsHashed(), Equals, false)

	// XXX SHOULD SET TIME to uDocTime HERE XXX
	t, err := xu.ParseTimestamp(uDocTime)
	c.Assert(err, IsNil)
	myList.setTimestamp(t)

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

	c.Assert(myList.IsHashed(), Equals, false)
	myList.SetDocHash()
	docHash := myList.GetDocHash()
	c.Assert(docHash, NotNil)
	c.Assert(myList.IsHashed(), Equals, true)
	ok := myList.Verify()
	c.Assert(ok, Equals, true)
	myDoc, err := myList.String()
	c.Assert(err, IsNil)

	// DEBUG
	fmt.Printf("MY_DOC - UNSIGNED:\n%s", myDoc)
	// END

	reader := strings.NewReader(myDoc)
	list2, err := ParseUnsignedBList(reader)
	c.Assert(err, IsNil)
	c.Assert(list2, NotNil)

	c.Assert(list2.Size(), Equals, uint(4))
	c.Assert(list2.IsHashed(), Equals, true)
	c.Assert(list2.Verify(), Equals, true)

	str, err := list2.String()
	c.Assert(err, IsNil)
	c.Assert(str, Equals, myDoc)

	// yes, this is fully redundant
	docHash2 := list2.GetDocHash()
	c.Assert(bytes.Equal(docHash2, docHash), Equals, true)

}
