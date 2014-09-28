package builds

// xlCrypto_go/builds/buildList.go

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	xc "github.com/jddixon/xlCrypto_go"
	xu "github.com/jddixon/xlUtil_go"
	"io"
	"strings"
	"time"
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
	PubKey *rsa.PublicKey
	DigSig []byte
	xc.BuildList
}

func NewSignedList(title string, pubkey *rsa.PublicKey) (
	sList *SignedList, err error) {

	if pubkey == nil {
		err = NilPublicKey
	} else if title == "" {
		err = NilTitle
	} else {
		// timestamp is set when it gets signed
		bList, err := xc.NewBuildList(title, 0)
		if err == nil {
			sList = &SignedList{
				PubKey:    pubkey,
				BuildList: *bList,
			}
		}
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
func (bl *SignedList) Size() uint {
	return uint(len(bl.Content))
}

/**
 * Return the Nth content item in string form, without any CRLF.
 */
func (bl *SignedList) Get(n uint) (s string, err error) {
	if n < 0 || bl.Size() <= n {
		err = NdxOutOfRange
	} else {
		i := bl.Content[n].(*Item)
		s = i.String()
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
		var item *Item
		item, err = NewItem(hash, name)
		if err == nil {
			bl.Content = append(bl.Content, item)
		}
	}
	return
}

/**
 * Return the SHA1 hash for the Nth Item.
 * XXX Should be modified to return a copy.
 */
func (bl *SignedList) GetItemHash(n uint) []byte {
	i := bl.Content[n].(*Item)
	return i.EHash
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
	i := bl.Content[n].(*Item)
	return i.Path
}

// DIG SIG //////////////////////////////////////////////////////////

func (sl *SignedList) IsSigned() bool {
	return len(sl.DigSig) > 0
}

func (sl *SignedList) GetDigSig() []byte {
	return sl.DigSig
}

func (sl *SignedList) SetDigSig(val []byte) {
	// XXX NEEDS BETTER VALIDATION
	sl.DigSig = make([]byte, len(val))
	copy(sl.DigSig, val)
}

/**
 * Set a timestamp and calculate a digital signature.  First
 * calculate the SHA1 hash of the pubKey, title, timestamp,
 * and content lines, excluding the terminating CRLF in each
 * case, then encrypt that using the RSA private key supplied.
 *
 * @param key RSAKey whose secret materials are used to sign
 */
func (sl *SignedList) Sign(skPriv *rsa.PrivateKey) (err error) {

	var (
		digSig, hash []byte
	)

	if sl.DigSig != nil {
		err = ListAlreadySigned
	} else if skPriv == nil {
		err = NilPrivateKey
	} else {
		sl.Timestamp = xu.Timestamp(time.Now().UnixNano())
		hash, err = sl.HashBody()
		if err == nil {
			digSig, err = rsa.SignPKCS1v15(
				rand.Reader, skPriv, crypto.SHA1, hash)
			if err == nil {
				sl.DigSig = digSig
			}
		}
		if err != nil {
			sl.Timestamp = 0 // restore to default
		}
	}
	return
}

/**
 * Verify that the BuildList agrees with its digital signature,
 * returning nil if it is correct and an appropriate error otherwise.
 */
func (sl *SignedList) Verify() (err error) {

	var hash []byte

	if sl.DigSig == nil {
		err = ListNotSigned
	} else {
		hash, err = sl.HashBody()
		if err == nil {
			err = rsa.VerifyPKCS1v15(sl.PubKey, crypto.SHA1, hash, sl.DigSig)
		}
	}
	return
}

// DOCUMENT HASH ////////////////////////////////////////////////////

/**
 * Return this SignedList's SHA1 hash, a byte array 20 bytes
 * long.  The hash is over first the public key in its 'wire' form
 * and then over the title.
 *
 * XXX This is completely different from the current Java implementation;
 * the two must be reconciled.
 */

func (sl *SignedList) GetHash() []byte {

	d := sha1.New()

	// public key in PKCS1 format
	pk, _ := xc.RSAPubKeyToWire(sl.PubKey)
	d.Write(pk)

	d.Write([]byte(sl.Title))
	return d.Sum(nil)
}

// SERIALIZATION ////////////////////////////////////////////////////

func (sList *SignedList) String() (s string, err error) {

	if sList.PubKey == nil {
		err = NilPublicKey
	} else {
		title, timestamp, pubKey := sList.Strings()

		// pubKey is newline-terminated
		pubKey = pubKey[:len(pubKey)-1]

		ss := []string{title, timestamp, pubKey}
		ss = append(ss, string(xc.CONTENT_START))
		for i := uint(0); err == nil && i < sList.Size(); i++ {
			var line string
			line, err = sList.Get(i)
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
			myDigSig := base64.StdEncoding.EncodeToString(sList.GetDigSig())
			ss = append(ss, myDigSig)
			s = strings.Join(ss, CRLF) + CRLF
		}
	}
	return
}

/**
 * Serialize the document header.  All lines are CRLF-terminated.
 * Subclasses are responsible for formatting their content lines,
 * without any termination.  If any error is encountered, this
 * function silently returns an empty string.
 *
 * PANICS if bl.PubKey is nil.
 */
func (bl *SignedList) Strings() (title, timestamp, pk string) {

	// title ------------------------------------------
	title = bl.Title

	// timestamp --------------------------------------
	timestamp = bl.Timestamp.String()

	// public key to SSH format -----------------------
	pkBytes, _ := xc.RSAPubKeyToDisk(bl.PubKey) // is newline-terminated
	pk = string(pkBytes)

	return
}

// PARSE/DESERIALIZATION ////////////////////////////////////////////

//func ParseSignedList(in io.Reader) (sList *SignedList, err error) {
//	var (
//		digSig, line []byte
//	)
//	bin := bufio.NewReader(in)
//	bList, err := xc.ParseBuildList(bin)
//	if err == nil {
//		sList = &SignedList{BuildList: *bList}
//		err = sList.ReadContents(bin)
//		if err == nil {
//			// try to read the digital signature line
//			line, err = xc.NextLineWithoutCRLF(bin)
//			if err == nil || err == io.EOF {
//				digSig, err = base64.StdEncoding.DecodeString(string(line))
//			}
//			if err == nil || err == io.EOF {
//				sList.SetDigSig(digSig)
//			}
//		}
//	}
//	if err == io.EOF {
//		err = nil
//	}
//	return
//}

// Read the header part of a signed list that has been serialized in disk
// format, returning a pointer to the deserialized object or an error.
// Subclasses should call this to get a pointer to the BuildList part
// of the subclass struct.  If the subclass is an XXXList, then expect
// the calling routine to be ParseXXXList()
//
func ParseSignedList(in io.Reader) (sList *SignedList, err error) {

	var (
		line   []byte
		pubKey *rsa.PublicKey
		title  string
		t      xu.Timestamp // binary form
	)
	bin := bufio.NewReader(in)

	// Read the header part -----------------------------------------
	line, err = xc.NextLineWithoutCRLF(bin)
	if err == nil {
		title = string(line)
		line, err = xc.NextLineWithoutCRLF(bin)
		if err == nil {
			t, err = xu.ParseTimestamp(string(line))
			if err == nil {
				line, err = xc.NextLineWithoutCRLF(bin)
				if err == nil {
					line = append(line, 10) // NEWLINE
					pubKey, err = xc.RSAPubKeyFromDisk(line)
					if err == nil {
						line, err = xc.NextLineWithoutCRLF(bin)
						if err == nil {
							if !bytes.Equal(line, xc.CONTENT_START) {
								err = xc.MissingContentStart
							}
						}
					}
				}
			}
		}
	}

	// Build and populate the SignedList object ---------------------
	if err == nil {
		var bList *xc.BuildList
		bList, err = xc.NewBuildList(title, t)
		if err == nil {
			sList = &SignedList{
				PubKey:    pubKey,
				BuildList: *bList,
			}
			// Read the content lines and then the dig sig ----------
			err = sList.ReadContents(bin)
			if err == nil {
				// try to read the digital signature line
				var digSig []byte
				line, err = xc.NextLineWithoutCRLF(bin)
				if err == nil || err == io.EOF {
					digSig, err = base64.StdEncoding.DecodeString(string(line))
					if err == nil || err == io.EOF {
						sList.SetDigSig(digSig)
						if err == io.EOF {
							err = nil
						}
					}
				}
			}

		}
	}
	return
}
