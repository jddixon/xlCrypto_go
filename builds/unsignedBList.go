package builds

// xlCrypto_go/builds/unsignedList.go

import (
	"bufio"
	//"bytes"
	//"encoding/base64"
	"fmt"
	xc "github.com/jddixon/xlCrypto_go"
	xu "github.com/jddixon/xlUtil_go"
	"io"
	"strings"
)

var _ = fmt.Print

/**
 * 2014-09-28:
 *
 * An UnsigedBList begins with a header.  This is followed by a
 * demarcator, then zero or more content lines, then a second
 * demarcator, and finally a base64-encoded SHA1 document hash.
 *
 * The header consists of the document title line and a timestamp line
 * in CCYY-MM-DD HH:MM:SS format.  Each of these is terminated with a
 * CRLF sequence, but the CRLF is dropped in calculating the document
 * hash.
 *
 * The Content section begins with a "# BEGIN CONTENT #" and ends with
 * an "# END CONTENT #" line.  Each line is CRLF-terminated.  Both lines
 * are ignored in calculating the document hash.
 *
 * Serialized, the Content section contains a list of files and their extended
 * hashes.  Each content line starts with base64-encoded extended hash
 * which is followed by a single space and then the file name, including
 * the POSIX path.  Lines end with CRLF.  The CRLF is ignored in
 * calculating the document hash.
 *
 * The extended hash in the content line is the base64-encoded SHA1 hash of
 * the contents of the file named.
 *
 * The document hash is the base64-encodd SHA1 hash of the title line
 * and timestamp lines (ie, the header lines) and then eah of the content
 * lines in order.  CRLF line terminators and content demarcators are
 * ignored in calculating the SHA1-hash.
 */
type UnsignedBList struct {
	Hash []byte
	xc.BuildList
}

func NewUnsignedBList(title string) (
	sList *UnsignedBList, err error) {

	bList, err := xc.NewBuildList(title, 0)
	if err == nil {
		sList = &UnsignedBList{BuildList: *bList}
	}
	return
}

func (ul *UnsignedBList) SetTimestamp(t xu.Timestamp) {
	ul.Timestamp = t
}

// BuildList ABSTRACT METHODS //////////////////////////////////

/**
 * Return the number of content lines
 */
func (ul *UnsignedBList) Size() uint {
	return uint(len(ul.Content))
}

/**
 * Return the Nth content item in string form, without any CRLF.
 */
func (ul *UnsignedBList) Get(n uint) (s string, err error) {
	if n < 0 || ul.Size() <= n {
		err = NdxOutOfRange
	} else {
		ptc := ul.Content[n].(*Item)
		s = ptc.String()
	}
	return
}

/**
 * Add a content line to the UnsignedBList.  In string form, the
 * content line begins with the extended hash of the Item
 * (the content hash if it is a data file) followed by a space
 * followed by the name of the Item.  If the name is a path,
 * the SEPARATOR character is a UNIX/Linux-style forward slash,
 * UnsignedBList.SEPARATOR.
 *
 * @param hash  extended hash of Item, its file key
 * @param name  file or path name of Item
 * @return      reference to this UnsignedBList, to ease chaining
 */
func (ul *UnsignedBList) Add(hash []byte, name string) (err error) {

	var item *Item
	item, err = NewItem(hash, name)
	if err == nil {
		ul.Content = append(ul.Content, item)
	}
	return
}

/**
 * Return the SHA1 hash for the Nth Item.
 * XXX Should be modified to return a copy.
 */
func (ul *UnsignedBList) GetItemHash(n uint) []byte {
	ptc := ul.Content[n].(*Item)
	return ptc.EHash
}

/**
 * Returns the path + fileName for the Nth content line, in
 * a form usable with the operating system.  That is, the
 * SEPARATOR is File.SEPARATOR instead of UnsignedBList.SEPARATOR,
 * if there is a difference.
 *
 * @param n content line
 * @return the path + file name for the Nth Item
 */
func (ul *UnsignedBList) GetPath(n uint) string {

	// XXX NEEDS VALIDATION
	ptc := ul.Content[n].(*Item)
	return ptc.Path
}

/**
 * Return the document header as a slice of strings, dropping CRLF
 * line terminators.
 *
 * If any error is encountered, this function silently returns an empty string.
 */
func (ul *UnsignedBList) Strings() (title, timestamp string) {

	// title ------------------------------------------
	title = ul.Title

	// timestamp --------------------------------------
	timestamp = ul.Timestamp.String()

	return
}

func (ul *UnsignedBList) String() (s string, err error) {

	title, timestamp := ul.Strings()

	ss := []string{title, timestamp}
	ss = append(ss, string(xc.CONTENT_START))
	for i := uint(0); err == nil && i < ul.Size(); i++ {
		var line string
		line, err = ul.Get(i)
		if err == nil || err == io.EOF {
			ss = append(ss, line)
			if err == io.EOF {
				err = nil
				break
			}
		}
	}
	if err == nil {
		ss = append(ss, string(xc.CONTENT_END))
		s = strings.Join(ss, CRLF) + CRLF
	}
	return
}
func ParseUnsignedBList(in io.Reader) (uList *UnsignedBList, err error) {

	// var line []byte

	bin := bufio.NewReader(in)
	bList, err := xc.ParseBuildList(bin)
	if err == nil {
		uList = &UnsignedBList{BuildList: *bList}
		err = ReadContents(bin, uList, false) // true = it's signed
	}
	if err == io.EOF {
		err = nil
	}
	return
}
