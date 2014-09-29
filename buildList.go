package crypto

// xlCrypto_go/buildList.go

import (
	"bufio"
	//"bytes"
	"crypto/sha1"
	"fmt"
	xu "github.com/jddixon/xlUtil_go"
	"io"
)

var _ = fmt.Print

var (
	CONTENT_START = []byte("# BEGIN CONTENT #")
	CONTENT_END   = []byte("# END CONTENT #")
)

/**
 * XXX NEEDS TO BE EDITED:
 *
 * In its serialized form a BuildList consists of a public key line,
 * a title line, a timestamp line, a number of content lines, and a
 * digital signature.  Each of the lines ends with a CR-LF sequence.
 * A blank line follows the last content line.  The timestamp (in
 * CCYY-MM-DD HH:MM:SS form) represents the time at which the list
 * was signed using the RSA private key corresponding to the key in
 * the public key line.
 *
 * The SHA1withRSA digital signature is on the entire BuildList excluding
 * the digital signature line.  All line endings are converted to
 * CRLF before taking the digital signature.
 *
 * The BuildList itself has a 20-byte extended hash, the 20-byte SHA1
 * digest of a function of the public key and the title.  This means
 * that the owner of the RSA key can create any number of documents
 * with the same hash but different timestamps with the intention
 * being that users can choose to regard the document with the most
 * recent timestamp as authentic.
 *
 * What the content line contains varies between subclasses.
 */

type BuildList struct {
	Title     string
	Timestamp xu.Timestamp  // set when signed or docHash set
	Content   []interface{} // []ItemI
}

func NewBuildList(title string, timestamp xu.Timestamp) (
	bl *BuildList, err error) {

	if title == "" {
		err = EmptyTitle
	} else {
		bl = &BuildList{
			Title:     title,
			Timestamp: timestamp,
		}
	}
	return
}

// PROPERTIES ///////////////////////////////////////////////////

func (bl *BuildList) GetContent() *[]interface{} {
	return &bl.Content
}

func (bl *BuildList) GetTitle() string {
	return bl.Title
}

/**
 * Return this BuildList's SHA1 hash, a byte array 20 bytes
 * long.  The hash is over first the public key in its 'wire' form
 * and then over the title.
 *
 * Subclass must implement.
 *
 * XXX This is completely different from the current Java implementation;
 * the two must be reconciled.
 */

func (bl *BuildList) GetHash() []byte {

	d := sha1.New()

	d.Write([]byte(bl.Title))
	return d.Sum(nil)
}

/**
 * The number of items in the list, excluding the header lines
 * (public key, title, timestamp) and the footer lines (blank
 * line, digital signature).
 *
 * @return the number of content items
 */
func (bl *BuildList) Size() (size uint) {
	// SUBCLASS MUST IMPLEMENT
	return
}

// DIGITAL SIGNATURE ////////////////////////////////////////////////

/**
 * Return the SHA1 hash of the BuildList, excluding the digital
 * signature but expecting the timestamp to have been set.
 */
func (bl *BuildList) HashBody() (hash []byte, err error) {
	d := sha1.New()

	// title ----------------------------------------------
	d.Write([]byte(bl.Title))

	// content lines --------------------------------------
	for i := uint(0); err == nil && i < bl.Size(); i++ {
		var line string
		line, err = bl.Get(i)
		if err == nil || err == io.EOF {
			d.Write([]byte(line))
			if err == io.EOF {
				err = nil
				break
			}
		}
	}
	if err == nil {
		hash = d.Sum(nil)
	}
	return
}

// SERIALIZATION ////////////////////////////////////////////////

/**
 * Return the Nth content item in String form, without any terminating CRLF.
 * Using code should permit the implementation to return io.EOF either
 * with the last valid line or an empty string and io.EOF on subsequent
 * calls.
 */
func (bl *BuildList) Get(n uint) (s string, err error) {

	/* SUBCLASSES MUST IMPLEMENT */

	err = NotImplemented
	return
}

// SERIALIZATION ////////////////////////////////////////////////////

func NextLineWithoutCRLF(in *bufio.Reader) (line []byte, err error) {
	line, err = in.ReadBytes('\n')
	if err == nil || err == io.EOF {
		line = line[:len(line)-1] // drop the \n
		lineLen := len(line)
		if lineLen > 0 && line[lineLen-1] == '\r' {
			line = line[:len(line)-1] // drop any \r
		}
	}
	return
}
