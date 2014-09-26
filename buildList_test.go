package crypto

// xlCrypto_go/signed_list_test.go

import (
	"bytes"
	"fmt"
	xr "github.com/jddixon/rnglib_go"
	. "gopkg.in/check.v1"
	"strings"
)

var _ = fmt.Print

/**
 * Generate a few random RSA keys, create MyLists, test.
 */
func (s *XLSuite) TestGenerateBuildList(c *C) {
	rng := xr.MakeSimpleRNG()
	_ = rng

	for i := 0; i < 8; i++ {

		// create and test signed list
		myList, err := NewMockBuildList("document 1")
		c.Assert(err, IsNil)
		c.Assert(myList, NotNil)

		// add a few lines
		count := uint(3 + rng.Intn(10))
		for i := uint(0); i < count; i++ {
			s := rng.NextFileName(16)
			n := myList.AddItem(s)
			c.Assert(n, Equals, i)
		}
		c.Assert(myList.Size(), Equals, count)

		// Generate a new BuildList from the serialization of the
		// current one, use it to test Reader constructor.
		myDoc := myList.String()
		c.Assert(myDoc, Not(Equals), "")

		// deserialize = parse it
		reader := strings.NewReader(myDoc)
		myList2, err := ParseMockBuildList(reader)
		c.Assert(err, IsNil)
		c.Assert(myList2, NotNil)
	}
}

func (s *XLSuite) TestListHash(c *C) {
	rng := xr.MakeSimpleRNG()
	_ = rng

	for i := 0; i < 8; i++ {
		myList, err := NewMockBuildList("document 1")
		c.Assert(err, IsNil)
		c.Assert(myList, NotNil)

		// add a few lines
		count := uint(3 + rng.Intn(10))
		for i := uint(0); i < count; i++ {
			s := rng.NextFileName(16)
			n := myList.AddItem(s)
			c.Assert(n, Equals, i)
		}
		c.Assert(myList.Size(), Equals, count)

		myHash := myList.GetHash()
		list2, err := NewMockBuildList("document 1")
		c.Assert(err, IsNil)
		hash2 := list2.GetHash()
		// title the same so hashes are the same
		c.Assert(bytes.Equal(myHash, hash2), Equals, true)

		list2, err = NewMockBuildList("document 2")
		c.Assert(err, IsNil)
		hash2 = list2.GetHash()
		// titles differ so hashes differ
		c.Assert(bytes.Equal(myHash, hash2), Equals, false)

		//      // a build list with the same key and title has same hash
		//      BuildList buildList = new BuildList("document 1")
		//      bHash = buildList.GetHash()
		//      c.AssertEquals (20, bHash.length)
		//      checkSameHash (bHash, myHash)
	}
}
