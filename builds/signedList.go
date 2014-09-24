package builds

// xlCrypto_go/builds/buildList.go

import (
	"bufio"
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	xc "github.com/jddixon/xlCrypto_go"
	"io"
	"strings"
)

var _ = fmt.Print

/**
 * Serialized, a build list is a list of files and their extended hashes.
 * Each content line starts with base64-encoded extended hash which is
 * followed by a single space and then the file name, including the
 * path.  Lines end with CRLF.
 *
 * The hash for a serialized SignedList, its title key, is the 20-byte
 * BuildList hash, an SHA1-based function of the SignedList's title and
 * RSA public key.
 *
 * The digital signature in the last line is calculated from the
 * SHA1 digest of the header lines (public key, title, and timestamp
 * lines, each CRLF-terminated) and the content lines.
 */
type SignedList struct {
	content []*xc.Item
	xc.BuildList
}

func NewSignedList(pubkey *rsa.PublicKey, title string) (
	sList *SignedList, err error) {

	bList, err := xc.NewBuildList(pubkey, title)
	if err == nil {
		sList = &SignedList{BuildList: *bList}
	}
	return
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
func (bl *SignedList) ReadContents(in *bufio.Reader) (err error) {

	for err == nil {
		var (
			hash, line []byte
			path       string
			item       *xc.Item
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
					item, err = xc.NewItem(hash, path)
					if err == nil {
						bl.content = append(bl.content, item)
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
func (bl *SignedList) Size() uint {
	return uint(len(bl.content))
}

/**
 * Return the Nth content item in string form, without any CRLF.
 */
func (bl *SignedList) Get(n uint) (s string, err error) {
	if n < 0 || bl.Size() <= n {
		err = xc.NdxOutOfRange
	} else {
		s = bl.content[n].String()
	}
	return
}

/**
 * Add a content line to the SignedList.  In string form, the
 * content line begins with the extended hash of the Item
 * (the content hash if it is a data file) followed by a space
 * followed by the name of the Item.  If the name is a path,
 * the SEPARATOR character is a UNIX/Linux-style forward slash,
 * SignedList.SEPARATOR.
 *
 * @param hash  extended hash of Item, its file key
 * @param name  file or path name of Item
 * @return      reference to this SignedList, to ease chaining
 */
func (bl *SignedList) Add(hash []byte, name string) (err error) {

	if bl.IsSigned() {
		err = CantAddToSignedList
	} else {
		var item *xc.Item
		item, err = xc.NewItem(hash, name)
		if err == nil {
			bl.content = append(bl.content, item)
		}
	}
	return
}

/**
 * Return the SHA1 hash for the Nth Item.
 * XXX Should be modified to return a copy.
 */
func (bl *SignedList) GetItemHash(n uint) []byte {
	return bl.content[n].EHash
}

/**
 * Returns the path + fileName for the Nth content line, in
 * a form usable with the operating system.  That is, the
 * SEPARATOR is File.SEPARATOR instead of SignedList.SEPARATOR,
 * if there is a difference.
 *
 * @param n content line
 * @return the path + file name for the Nth Item
 */
func (bl *SignedList) GetPath(n uint) string {

	// XXX NEEDS VALIDATION
	return bl.content[n].Path
}

func (bl *SignedList) String() (s string) {

	var (
		err error
	)
	pubKey, title, timestamp := bl.Strings()

	// we leave out pubKey because it is newline-terminated
	ss := []string{title, timestamp}
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
		myDigSig := base64.StdEncoding.EncodeToString(bl.GetDigSig())
		ss = append(ss, myDigSig)
		s = string(pubKey) + strings.Join(ss, CRLF) + CRLF
	}
	return
}
func ParseSignedList(in io.Reader) (sList *SignedList, err error) {
	var (
		digSig, line []byte
	)
	bin := bufio.NewReader(in)
	bList, err := xc.ParseBuildList(bin)
	if err == nil {
		sList = &SignedList{BuildList: *bList}
		err = sList.ReadContents(bin)
		if err == nil {
			// try to read the digital signature line
			line, err = xc.NextLineWithoutCRLF(bin)
			if err == nil || err == io.EOF {
				digSig, err = base64.StdEncoding.DecodeString(string(line))
			}
			if err == nil || err == io.EOF {
				sList.SetDigSig(digSig)
			}
		}
	}
	if err == io.EOF {
		err = nil
	}
	return
}