package filters

// xlCrypto_go/filters/key_selector_test.go

import (
	"fmt" // DEBUG
	xr "github.com/jddixon/rnglib_go"
	. "gopkg.in/check.v1"
)

var _ = fmt.Print

const (
	NUM_TEST_KEYS = 16
)

func setUpTestKS() (
	ks *KeySelector,
	m,
	k,
	v uint, // size of test values (160 = SHA1, 256 = SHA3)
	keys [][]byte) {

	m = 20 // default
	k = 8
	v = 20 // v is the number of bytes in a test value (key)

	// Create the array of keys to be used to test the KeySelector.
	// These are v=20 byte keys, so SHA1 hashes.
	keys = make([][]byte, NUM_TEST_KEYS)
	for i := 0; i < NUM_TEST_KEYS; i++ {
		keys[i] = make([]byte, v)
	}
	return
}

// DEBUG
func (s *XLSuite) dumpB(c *C, b []byte) {
	for i := uint(0); i < uint(len(b)); i++ {
		fmt.Printf("%02x", b[i])
	}
	fmt.Println()
}

// END
func (s *XLSuite) TestBitSelection(c *C) {
	if VERBOSITY > 0 {
		fmt.Println("TEST_BIT_SELECTION")
	}
	var err error
	ks, m, k, v, keys := setUpTestKS()

	// Set up bit selectors for NUM_TEST_KEYS test keys.  Each
	// bit selector is populated with a different value.
	for i := 0; i < NUM_TEST_KEYS; i++ {
		bitOffsets := make([]byte, k)
		for j := uint(0); j < k; j++ {
			bitOffsets[j] = byte((j*k + j) % 8)
		}
		s.setBitOffsets(c, &keys[i], bitOffsets)
	}

	for i := uint(0); false && i < NUM_TEST_KEYS; i++ {
		ks, err = NewKeySelector(m, k, keys[i])
		c.Assert(err, IsNil)
		for j := uint(0); j < k; j++ {
			c.Assert(ks.bitOffset[j], Equals, byte((j*k+j)%8))
		}
	}
	_ = v
} // GEEP

// Set the bit selectors, which are the k KEY_SEL_BITS-bit values
// at the beginning of a key.
// @param b   key, expected to be at least 20 bytes long
// @param val array of key values, expected to be k long
func (s *XLSuite) setBitOffsets(c *C, b *[]byte, val []byte) {

	vLen := uint(len(val))
	var curBit, curByte uint

	for i := uint(0); i < vLen; i++ {
		curByte = curBit / 8           // byte offset in b
		tBit := curBit - (curByte * 8) // bit offset
		uBits := 8 - tBit

		// mask value to KEY_SEL_BITS bits
		unVal := val[i] & UNMASK[KEY_SEL_BITS]

		if tBit == 0 {
			// we are aligned, so just OR it in
			(*b)[curByte] |= unVal

		} else if uBits >= KEY_SEL_BITS {
			// it will fit in this byte
			(*b)[curByte] |= (unVal << tBit)

		} else {
			// some goes in this byte, some in the next
			valThisByte := (unVal & UNMASK[uBits])
			(*b)[curByte] |= valThisByte << tBit

			valNextByte := (unVal >> uBits)
			(*b)[curByte+1] |= valNextByte
		}
		curBit += KEY_SEL_BITS
	}
}

// Set the word selectors, which are the k wordSelBits-bit values
// following the bit sectors in the key.
func (s *XLSuite) setWordOffsets(c *C, b *[]byte, val []uint, m, k uint) {
	// 2 ^ 6 == 64, number of bits in a uint64
	wordSelBits := m - 6
	wordSelMask := (uint(1) << wordSelBits) - 1
	bytesInV := (wordSelBits + 7) / 8
	var bitsLastByte uint
	if bytesInV*8 == wordSelBits {
		bitsLastByte = 8
	} else {
		bitsLastByte = wordSelBits - (bytesInV-1)*8
	}
	vLen := uint(len(val))

	var curTByte uint           // byte offset in b
	curTBit := k * KEY_SEL_BITS // bit offset in b

	// iterate through the test values, merging them into target
	for i := uint(0); i < vLen; i++ {

		// be paranoid: mask test value to wordSelBits bits
		maskedVal := val[i] & wordSelMask
		for j := uint(0); j < bytesInV; j++ {
			thisVByte := byte(maskedVal >> (j * uint(8)))

			bitsThisVByte := uint(8)
			if j == (bytesInV - 1) {
				bitsThisVByte = bitsLastByte
			}
			// these point into the target, b
			curTByte = curTBit / 8
			tBit := curTBit - (curTByte * 8) // bit offset

			if tBit == 0 {
				// we just assign it in, trusting b was all zeroes
				(*b)[curTByte] = byte(thisVByte)

			} else {
				// we have to shift
				fBits := 8 - tBit // unused bits this byte
				if bitsThisVByte <= fBits {
					// it will fit in this byte
					value := thisVByte << tBit
					(*b)[curTByte] |= value

				} else {
					// we have to split it over two target bytes
					lValue := (thisVByte & UNMASK[fBits]) << tBit
					(*b)[curTByte] |= lValue

					rValue := thisVByte >> fBits
					(*b)[curTByte+1] |= rValue
				}
			}
			curTBit += bitsThisVByte
		}
	}
}

func (s *XLSuite) doTestKeySelector64(c *C, rng *xr.PRNG, usingSHA1 bool, m uint) {

	var v uint     // length of byte array
	if usingSHA1 { //
		v = uint(20) // bytes
	} else {
		v = uint(32)
	}
	b := make([]byte, v)   // value being inserted into filter
	k := uint((v * 8) / m) // number of hash functions

	bitSel := make([]byte, k)
	wordSel := make([]uint, k)
	// 2^6 is 64, number of bits in a uint64
	wordsInFilter := 1 << (m - uint(6))

	for i := uint(0); i < k; i++ {
		bitSel[i] = byte(rng.Intn(64))
		wordSel[i] = uint(rng.Intn(wordsInFilter))
	}

	// concatenate the key selectors at the front
	s.setBitOffsets(c, &b, bitSel)

	// append the word selectors
	s.setWordOffsets(c, &b, wordSel, m, k)

	// create an m,k filter
	filter, err := NewBloomSHA(m, k)
	c.Assert(err, IsNil)

	// verify that the expected bits are NOT set
	for i := uint(0); i < k; i++ {
		filterWord := filter.Filter[wordSel[i]]
		bitSelector := uint64(1) << bitSel[i]
		bitVal := filterWord & bitSelector
		c.Assert(bitVal == 0, Equals, true)
	}

	// insert the value b
	filter.Insert(b)

	// verify that all of the expected bits are set
	for i := uint(0); i < k; i++ {
		filterWord := filter.Filter[wordSel[i]]
		bitSelector := uint64(1) << bitSel[i]
		bitVal := filterWord & bitSelector
		c.Assert(bitVal == 0, Equals, false)
	}
}
func (s *XLSuite) TestKeySelector64(c *C) {

	rng := xr.MakeSimpleRNG()
	// m := uint(10 + rng.Intn(15))	// so 10..24
	s.doTestKeySelector64(c, rng, true, 24)
	s.doTestKeySelector64(c, rng, false, 24)
}
