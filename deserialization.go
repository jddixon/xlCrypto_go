package crypto

import (
	"errors"
	"fmt"
	"strings"
)

// Return the next non-blank line in the slice of strings, trimmed.
// This line and any preceding blank lines are removed from the slice.
func NextNBLine(lines *[]string) (s string, err error) {
	if lines != nil {
		for len(*lines) > 0 {
			s = strings.TrimSpace((*lines)[0])
			*lines = (*lines)[1:]
			if s != "" {
				return
			}
		}
		err = ExhaustedStringArray
	}
	return
}

// Given the opening line of the PEM serializaton of an RSA Public Key,
// and a pointer to an array of strings which should begin with the rest
// of the PEM serialization, return the entire PEM serialization as a
// single string.
func CollectPEMRSAPublicKey(s string, ss *[]string) (what []byte, err error) {

	var x []string
	x = append(x, s)
	if x[0] != "-----BEGIN PUBLIC KEY-----" {
		msg := fmt.Sprintf("PEM public key cannot begin with %s", x[0])
		err = errors.New(msg)
	} else {
		for err == nil {
			s, err = NextNBLine(ss)
			if err == nil {
				x = append(x, s)
				if s == "-----END PUBLIC KEY-----" {
					break
				}
			}
		}
	}
	if err == nil {
		what = []byte(strings.Join(x, "\n"))
	}
	return
}
