package sign

//go:generate runGoMobile.sh

import (
	crypto_rand "crypto/rand" // Custom so it's clear which rand we're using.
	"encoding/hex"

	"github.com/pkg/errors"
	"golang.org/x/crypto/nacl/sign"
)

type KeyPair struct {
	PrivateKey string
	PublicKey  string
}

func GenerateKey() (*KeyPair, error) {
	publicKey, privateKey, err := sign.GenerateKey(crypto_rand.Reader)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to generate identity key pair")
	}

	keyPair := &KeyPair{
		PrivateKey: hex.EncodeToString(privateKey[:]),
		PublicKey:  hex.EncodeToString(publicKey[:]),
	}

	return keyPair, err
}

func Sign(privateKeyHex string, message string) (string, error) {
	var err error
	var privateKey [64]byte

	bytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return "", errors.Wrap(err, "Failed to decode hex string to bytes")
	}
	copy(privateKey[:], bytes)

	signedBytes := sign.Sign(nil, []byte(message), &privateKey)
	return hex.EncodeToString(signedBytes[:]), err
}

func Open(publicKeyHex string, signedMessage string) (string, error) {
	var publicKey [32]byte
	var err error
	bytes, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return "", errors.Wrap(err, "Failed to decode hex key to byte")
	}
	copy(publicKey[:], bytes)

	signedMessageBytes, err := hex.DecodeString(signedMessage)
	if err != nil {
		return "", errors.Wrap(err, "Failed to decode signed message hex to bytes")
	}

	message, ok := sign.Open(nil, signedMessageBytes, &publicKey)
	if !ok {
		return "", errors.New("Failed to verify signed message")
	}

	return string(message), nil
}
