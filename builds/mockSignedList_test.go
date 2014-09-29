package builds

// xlCrypto_go/builds/mockBuildList_test.go
//
// The file has the _test suffix to limit MockBuildList's visibility
// to test runs.

// XXX ==============================================================
// XXX MOVED HERE FROM PARENT DIRECTORY.  PROBABLY SHOULD BE DROPPED.
// XXX ==============================================================

import (
	"bufio"
	"bytes"
	"fmt"
	xc "github.com/jddixon/xlCrypto_go"
	"io"
)

var _ = fmt.Print

type MockItem struct {
	Hash []byte
	Path string
}

func NewMockItem(s string) *MockItem {
	return &MockItem{Path: s}
}
func (mi *MockItem) GetHash() []byte { return mi.Hash }
func (mi *MockItem) GetPath() string { return mi.Path }

type MockBuildList struct {
	xc.BuildList
}

func NewMockBuildList(title string) (
	msl *MockBuildList, err error) {

	bl, err := xc.NewBuildList(title, 0)
	if err == nil {
		msl = &MockBuildList{
			BuildList: *bl,
		}
	}
	return
}

/**
 * Add an item to the Content, returning its zero-based index.
 */
func (msl *MockBuildList) AddItem(s string) (n uint) {
	n = uint(len(msl.Content)) // index of this item
	mi := NewMockItem(s)
	msl.Content = append(msl.Content, &mi)
	return
}

// Return the Nth content item in string form, without any CRLF.
func (msl *MockBuildList) Get(n uint) (s string, err error) {
	if n < 0 || msl.Size() <= n {
		err = NdxOutOfRange
	} else {
		item := msl.Content[n].(*MockItem)
		s = item.GetPath()
	}
	return
}

func (msl *MockBuildList) ReadContents(in *bufio.Reader) (err error) {

	for err == nil {
		var line []byte
		line, err = xc.NextLineWithoutCRLF(in)
		if err == nil || err == io.EOF {
			if bytes.Equal(line, xc.CONTENT_END) {
				break
			} else {
				mi := NewMockItem(string(line))
				msl.Content = append(msl.Content, mi)
			}
		}
	}
	return
}
func (msl *MockBuildList) Size() uint {
	return uint(len(msl.Content))
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
	title := msl.BuildList.Strings()
	ss = append(ss, title)

	// content lines ----------------------------------
	ss = append(ss, string(xc.CONTENT_START))
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
	return
}

func ParseMockBuildList(in io.Reader) (msl *MockBuildList, err error) {

	bin := bufio.NewReader(in)
	sl, err := xc.ParseBuildList(bin)
	if err == nil {
		msl = &MockBuildList{BuildList: *sl}
		err = msl.ReadContents(bin)
		//if err == nil {
		//	// try to read the digital signature line
		//	line, err = NextLineWithoutCRLF(bin)
		//	if err == nil || err == io.EOF {
		//		digSig, err = base64.StdEncoding.DecodeString(string(line))
		//	}
		//	if err == nil || err == io.EOF {
		//		msl.DigSig = digSig
		//	}
		//}
	}
	if err == io.EOF {
		err = nil
	}
	return
}
