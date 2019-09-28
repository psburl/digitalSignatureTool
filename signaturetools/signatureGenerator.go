package signaturetools

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io/ioutil"
)

type SignMessage struct {
	Message   string
	Signature string
}

func SignText(message string, privateKey *rsa.PrivateKey) SignMessage {

	var signMessage SignMessage
	signMessage.Message = message
	byteMessage := []byte(message)
	hashed := sha256.Sum256(byteMessage)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	checkError(err)
	signMessage.Signature = base64.StdEncoding.EncodeToString(signature)
	return signMessage
}

func VerifySign(signMessage SignMessage, pubkey *rsa.PublicKey) (bool, error) {
	sig, _ := base64.StdEncoding.DecodeString(signMessage.Signature)
	hashed := sha256.Sum256([]byte(signMessage.Message))
	err := rsa.VerifyPKCS1v15(pubkey, crypto.SHA256, hashed[:], sig)
	if err != nil {
		return false, err
	}
	return true, nil
}

func ReadPublicKey(path string) (*rsa.PublicKey, error) {
	key, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(key)
	der, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return der, err
}

func ReadPrivateKey(path string) (*rsa.PrivateKey, error) {
	key, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(key)
	der, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return der, err
}
