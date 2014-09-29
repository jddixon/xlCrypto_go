package builds

// xlCrypto_go/builds/unsignedList.go

import (
	"bufio"
	"bytes"
	"encoding/base64"
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
type UnsignedList struct {
	Hash []byte
	xc.BuildList
}

func NewUnsignedList(title string) (
	sList *UnsignedList, err error) {

	bList, err := xc.NewBuildList(title, 0)
	if err == nil {
		sList = &UnsignedList{BuildList: *bList}
	}
	return
}

func (ul *UnsignedList) SetTimestamp(t xu.Timestamp) {
	ul.Timestamp = t
}

// BuildList ABSTRACT METHODS //////////////////////////////////

/**
 * Read a series of content lines, each consisting of a hash
 * followed by a space followed by a file name.  The hash is
 * base-64 encoded.
 *
 * The text of the line, excluding the line terminator, is
 * included in the digest.
 */
func (bl *UnsignedList) ReadContents(in *bufio.Reader) (err error) {

	for err == nil {
		var (
			hash, line []byte
			path       string
			item       *Item
		)
		line, err = xc.NextLineWithoutCRLF(in)
		if err == nil || err == io.EOF {
			if bytes.Equal(line, xc.CONTENT_END) {
				break
			} else {
				// Parse the line.  We expect it to consist of a base64-
				// encoded hash followed by a space followed by a POSIX
				// path.
				line = bytes.Trim(line, " \t")
				if len(line) == 0 {
					err = EmptyContentLine
				} else {
					parts := bytes.Split(line, SPACE_SEP)
					if len(parts) != 2 {
						err = IllFormedContentLine
					} else {
						var count int
						e := base64.StdEncoding
						maxLen := e.DecodedLen(len(parts[0]))
						hash = make([]byte, maxLen)
						count, err = e.Decode(hash, parts[0])
						if err == nil {
							path = string(parts[1])
						}
						hash = hash[:count]
					}
				}
				if err == nil {
					item, err = NewItem(hash, path)
					if err == nil {
						bl.Content = append(bl.Content, item)
					}
				}
			}
		}
	}
	return
}

/**
 * Return the number of content lines
 */
func (bl *UnsignedList) Size() uint {
	return uint(len(bl.Content))
}

/**
 * Return the Nth content item in string form, without any CRLF.
 */
func (bl *UnsignedList) Get(n uint) (s string, err error) {
	if n < 0 || bl.Size() <= n {
		err = NdxOutOfRange
	} else {
		ptc := bl.Content[n].(*Item)
		s = ptc.String()
	}
	return
}

/**
 * Add a content line to the UnsignedList.  In string form, the
 * content line begins with the extended hash of the Item
 * (the content hash if it is a data file) followed by a space
 * followed by the name of the Item.  If the name is a path,
 * the SEPARATOR character is a UNIX/Linux-style forward slash,
 * UnsignedList.SEPARATOR.
 *
 * @param hash  extended hash of Item, its file key
 * @param name  file or path name of Item
 * @return      reference to this UnsignedList, to ease chaining
 */
func (bl *UnsignedList) Add(hash []byte, name string) (err error) {

	var item *Item
	item, err = NewItem(hash, name)
	if err == nil {
		bl.Content = append(bl.Content, item)
	}
	return
}

/**
 * Return the SHA1 hash for the Nth Item.
 * XXX Should be modified to return a copy.
 */
func (bl *UnsignedList) GetItemHash(n uint) []byte {
	ptc := bl.Content[n].(*Item)
	return ptc.EHash
}

/**
 * Returns the path + fileName for the Nth content line, in
 * a form usable with the operating system.  That is, the
 * SEPARATOR is File.SEPARATOR instead of UnsignedList.SEPARATOR,
 * if there is a difference.
 *
 * @param n content line
 * @return the path + file name for the Nth Item
 */
func (bl *UnsignedList) GetPath(n uint) string {

	// XXX NEEDS VALIDATION
	ptc := bl.Content[n].(*Item)
	return ptc.Path
}

func (bl *UnsignedList) String() (s string, err error) {

	title := bl.Strings()

	// XXX POSSIBLY ADD timestamp
	ss := []string{title}
	ss = append(ss, string(xc.CONTENT_START))
	for i := uint(0); err == nil && i < bl.Size(); i++ {
		var line string
		line, err = bl.Get(i)
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
func ParseUnsignedList(in io.Reader) (sList *UnsignedList, err error) {

	// var line []byte

	bin := bufio.NewReader(in)
	bList, err := xc.ParseBuildList(bin)
	if err == nil {
		sList = &UnsignedList{BuildList: *bList}
		err = sList.ReadContents(bin)
	}
	if err == io.EOF {
		err = nil
	}
	return
}
