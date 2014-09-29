package builds

// xlCrypto_go/builds/readContents.go

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	xc "github.com/jddixon/xlCrypto_go"
	"io"
)

var _ = fmt.Print

/**
 * Read a series of content lines, each consisting of a hash
 * followed by a space followed by a file name.  The hash is
 * base-64 encoded.
 *
 * The text of the line, excluding the line terminator, is
 * included in the digest.
 */
func ReadContents(in *bufio.Reader, bList xc.BuildListI, isSigned bool) (
	err error) {

	// XXX NONSENSE
	var bl xc.BuildListI
	if isSigned {
		bl = bList.(*SignedBList)
	} else {
		bl = bList.(*UnsignedBList)
	}
	// END NONSENSE

	content := bl.GetContent()
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
						*content = append(*content, item)
					}
				}
			}
		}
	}
	return
}
