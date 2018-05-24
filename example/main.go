package main

import (
	"fmt"

	signer "github.com/spid37/nacl/sign"
)

func main() {
	keyPair, _ := signer.GenerateKey()
	fmt.Printf("Got the Private Key: %s\n", keyPair.PrivateKey)
	fmt.Printf("Got the PublicKey Key: %s\n", keyPair.PublicKey)
	signedMessage, _ := signer.Sign(keyPair.PrivateKey, "This is a message")
	fmt.Printf("Signed message: %s\n", signedMessage)
	message, _ := signer.Open(keyPair.PublicKey, signedMessage)
	fmt.Printf("Open message: %s\n", message)
}
