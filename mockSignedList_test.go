package crypto

// xlCrypto_go/mockBuildList_test.go
//
// The file has the _test suffix to limit MockBuildList's visibility
// to test runs.

import (
	"bufio"
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
)

var _ = fmt.Print

type MockBuildList struct {
	content []string
	BuildList
}

func NewMockBuildList(pubKey *rsa.PublicKey, title string) (
	msl *MockBuildList, err error) {

	sl, err := NewBuildList(pubKey, title)
	if err == nil {
		msl = &MockBuildList{
			BuildList: *sl,
		}
	}
	return
}

func (msl *MockBuildList) AddItem(s string) (n uint) {
	n = uint(len(msl.content)) // index of this item
	msl.content = append(msl.content, s)
	return
}

// Return the Nth content item in string form, without any CRLF.
func (msl *MockBuildList) Get(n uint) (s string, err error) {
	if n < 0 || msl.Size() <= n {
		err = NdxOutOfRange
	} else {
		s = msl.content[n]
	}
	return
}

func (msl *MockBuildList) ReadContents(in *bufio.Reader) (err error) {

	for err == nil {
		var line []byte
		line, err = NextLineWithoutCRLF(in)
		if err == nil || err == io.EOF {
			if bytes.Equal(line, CONTENT_END) {
				break
			} else {
				msl.content = append(msl.content, string(line))
			}
		}
	}
	return
}
func (msl *MockBuildList) Size() uint {
	return uint(len(msl.content))
}

/**
 * Serialize the entire document.  All lines are CRLF-terminated.
 * If any error is encountered, this function silently returns an
 * empty string.
 */
func (msl *MockBuildList) String() (s string) {

	var (
		err error
		ss  []string
	)
	pk, title, timestamp := msl.BuildList.Strings()
	ss = append(ss, title)
	ss = append(ss, timestamp)

	// content lines ----------------------------------
	ss = append(ss, string(CONTENT_START))
	for i := uint(0); err == nil && i < msl.Size(); i++ {
		var line string
		line, err = msl.Get(i)
		if err == nil || err == io.EOF {
			ss = append(ss, line)
			if err == io.EOF {
				err = nil
				break
			}
		}
	}
	if err == nil {
		ss = append(ss, string(CONTENT_END))

		myDigSig := base64.StdEncoding.EncodeToString(msl.DigSig)
		ss = append(ss, myDigSig)
		s = string(pk) + strings.Join(ss, CRLF) + CRLF
	}
	return
}

func ParseMockBuildList(in io.Reader) (msl *MockBuildList, err error) {

	var (
		digSig, line []byte
	)
	bin := bufio.NewReader(in)
	sl, err := ParseBuildList(bin)
	if err == nil {
		msl = &MockBuildList{BuildList: *sl}
		err = msl.ReadContents(bin)
		if err == nil {
			// try to read the digital signature line
			line, err = NextLineWithoutCRLF(bin)
			if err == nil || err == io.EOF {
				digSig, err = base64.StdEncoding.DecodeString(string(line))
			}
			if err == nil || err == io.EOF {
				msl.DigSig = digSig
			}
		}
	}
	if err == io.EOF {
		err = nil
	}
	return
}
