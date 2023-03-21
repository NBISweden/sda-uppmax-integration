package testhelpers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
)

// CreateECkeys creates the EC key pair
func CreateECkeys(path string) (string, error) {
	privatekey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}

	// dump private key to file
	privateKeyBytes, _ := x509.MarshalECPrivateKey(privatekey)
	privateKeyBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	prKeyPath := path + "/dummy.ec.pem"
	privatePem, err := os.Create(prKeyPath)
	if err != nil {
		return "", err
	}
	err = pem.Encode(privatePem, privateKeyBlock)
	if err != nil {
		return "", err
	}

	return prKeyPath, nil
}
