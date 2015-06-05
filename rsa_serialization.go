package crypto

// xlCrypto_go/rsa_serialization.go

import (
	"code.google.com/p/go.crypto/ssh"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

var _ = fmt.Print

// CONVERSION TO AND FROM WIRE FORMAT ///////////////////////////////

// Serialize an RSA public key to wire format
func RSAPubKeyToWire(pubKey *rsa.PublicKey) ([]byte, error) {

	return x509.MarshalPKIXPublicKey(pubKey)
}

// Deserialize an RSA public key from wire format
func RSAPubKeyFromWire(data []byte) (pub *rsa.PublicKey, err error) {
	pk, err := x509.ParsePKIXPublicKey(data)
	if err == nil {
		pub = pk.(*rsa.PublicKey)
	}
	return
}

// Serialize an RSA private key to wire format
func RSAPrivateKeyToWire(privKey *rsa.PrivateKey) (data []byte, err error) {
	data = x509.MarshalPKCS1PrivateKey(privKey)
	return
}

// Deserialize an RSA private key from wire format
func RSAPrivateKeyFromWire(data []byte) (key *rsa.PrivateKey, err error) {
	return x509.ParsePKCS1PrivateKey(data)
}

// CONVERSION TO AND FROM SSH FORMAT ////////////////////////////////

// Serialize an RSA public key to disk format, specifically to the
// format used by SSH. Should return nil if the conversion fails.
func RSAPubKeyToDisk(rsaPubKey *rsa.PublicKey) (out []byte, err error) {
	pubKey, err := ssh.NewPublicKey(rsaPubKey)
	if err == nil {
		out = ssh.MarshalAuthorizedKey(pubKey)
	}
	return out, nil
}

// Deserialize an RSA public key from the format used in SSH
// key files
func RSAPubKeyFromDisk(data []byte) (*rsa.PublicKey, error) {
	// out, _, _, _, ok := ssh.ParseAuthorizedKey(data)
	out, _, _, _, ok := ParseAuthorizedKey(data)
	_ = out // DEBUG
	if ok {
		return out, nil
	} else {
		return nil, NotAnRSAPublicKey
	}
}

// DEPRECATED ///////////////////////////////////////////////////////
func RSAPrivateKeyToDisk(privKey *rsa.PrivateKey) ([]byte, error) {
	return RSAPrivateKeyToPEM(privKey)
}
func RSAPrivateKeyFromDisk(data []byte) (key *rsa.PrivateKey, err error) {
	return RSAPrivateKeyFromPEM(data)
}

// CONVERSION TO AND FROM PEM FORMAT ////////////////////////////////

// Serialize an RSA private key to disk format
func RSAPrivateKeyToPEM(
	privKey *rsa.PrivateKey) (data []byte, err error) {

	if privKey == nil {
		err = NilData
	} else {
		data509 := x509.MarshalPKCS1PrivateKey(privKey)
		if data509 == nil {
			err = X509ParseOrMarshalError
		} else {
			block := pem.Block{Bytes: data509}
			data = pem.EncodeToMemory(&block)
		}
	}
	return
}

// Deserialize an RSA private key from disk format
func RSAPrivateKeyFromPEM(data []byte) (
	key *rsa.PrivateKey, err error) {

	if data == nil {
		err = NilData
	} else {
		block, _ := pem.Decode(data)
		if block == nil {
			err = PemEncodeDecodeFailure
		} else {
			key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		}
	}
	return
}

// Serialize an RSA public key to PEM format.
func RSAPubKeyToPEM(rsaPubKey *rsa.PublicKey) (out []byte, err error) {
	pubDer, err := RSAPubKeyToWire(rsaPubKey)
	if err == nil {
		blk := pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubDer,
		}
		out = pem.EncodeToMemory(&blk)
	}
	return
}

// Deserialize an RSA public key from PEM format.
func RSAPubKeyFromPEM(data []byte) (pk *rsa.PublicKey, err error) {
	// extract the PEM block
	blk, rest := pem.Decode(data)
	_ = rest

	// if extraction succeeded, blk.bytes should contain the DER
	if blk != nil {
		obj, err := x509.ParsePKIXPublicKey(blk.Bytes)
		if err == nil {
			switch t := obj.(type) {
			default:
				msg := fmt.Sprintf(
					"expected RSA public key, got %v", t)
				err = errors.New(msg)
			case *rsa.PublicKey:
				pk = obj.(*rsa.PublicKey)
			}
		}
	}
	return
}
