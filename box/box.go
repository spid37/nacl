package box

//go:generate runGoMobile.sh

import (
	crypto_rand "crypto/rand" // Custom so it's clear which rand we're using.
	"encoding/hex"
	"io"

	"github.com/davecgh/go-spew/spew"
	"github.com/pkg/errors"
	"golang.org/x/crypto/nacl/box"
)

// KeyPair public and private key in hex string
type KeyPair struct {
	PrivateKey string
	PublicKey  string
}

func GenerateKey() (*KeyPair, error) {
	publicKey, privateKey, err := box.GenerateKey(crypto_rand.Reader)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to generate encryption key pair")
	}

	keyPair := &KeyPair{
		PrivateKey: hex.EncodeToString(privateKey[:]),
		PublicKey:  hex.EncodeToString(publicKey[:]),
	}

	return keyPair, err
}

func hexStringTo32Bytes(publicKey string) (*[32]byte, error) {
	keyBytes := new([32]byte)
	var err error
	bytes, err := hex.DecodeString(publicKey)
	if err != nil {
		return keyBytes, errors.Wrap(err, "Failed to decode hex string to byte")
	}
	copy(keyBytes[:], bytes)

	return keyBytes, err
}

func SharedKey(peerPublicKey, privateKey string) (string, error) {
	spew.Dump(peerPublicKey, privateKey)
	peerPublicKeyBytes, err := hexStringTo32Bytes(peerPublicKey)
	if err != nil {
		return "", err
	}
	privateKeyBytes, err := hexStringTo32Bytes(privateKey)
	if err != nil {
		return "", err
	}

	// generate shared key
	var sharedKey [32]byte
	box.Precompute(&sharedKey, peerPublicKeyBytes, privateKeyBytes)

	return hex.EncodeToString(sharedKey[:]), nil
}

func Seal(sharedKey string, message string) (string, error) {
	var err error

	sharedKeyBytes, err := hexStringTo32Bytes(sharedKey)
	if err != nil {
		return "", err
	}

	var nonce [24]byte
	if _, err = io.ReadFull(crypto_rand.Reader, nonce[:]); err != nil {
		err = errors.Wrap(err, "Failed generating nonce")
		return "", err
	}

	encryptedMessage := box.SealAfterPrecomputation(
		nonce[:],
		[]byte(message),
		&nonce,
		sharedKeyBytes,
	)
	return hex.EncodeToString(encryptedMessage), nil
}

// OpenSealedMessage
func Open(sharedKey string, encryptedMessageHex string) (string, error) {
	sharedKeyBytes, err := hexStringTo32Bytes(sharedKey)
	if err != nil {
		return "", err
	}

	messageWithNonce, err := hex.DecodeString(encryptedMessageHex)
	if err != nil {
		err = errors.Wrap(err, "Failed to decode encrypted message hex to bytes")
		return "", err
	}

	nonce := new([24]byte)
	// message must be longer thatn the nonce
	if len(messageWithNonce) < len(nonce) {
		err = errors.New("Message data too short")
		return "", err
	}
	// extract nonce
	copy(nonce[:], messageWithNonce[:24])
	// extract message
	encryptedMessage := messageWithNonce[24:]

	decryptedMessage, ok := box.OpenAfterPrecomputation(
		nil,
		encryptedMessage,
		nonce,
		sharedKeyBytes,
	)
	if !ok {
		return "", errors.New("Failed to unseal message")
	}

	return string(decryptedMessage), nil
}
