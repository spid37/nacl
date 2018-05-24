package sign

import (
	"fmt"
	"testing"
)

const testMessage = "This is a test message!"
const testPublicKey = "5658b0026440c74a745e1e5d4414c931dfc4b9a194de3993cab35a577e5c1992"
const testPrivateKey = "bba57f7542fa6ad084374ff7b84f6281b2f9fd197019013e10820c821f674f9e5658b0026440c74a745e1e5d4414c931dfc4b9a194de3993cab35a577e5c1992"
const testSignedMessage = "7065fd901693db06956a53214ae64f257f78ac08e3d48107163d944084bb8bd06b7362c522d0232ce588603c0d3f78a97205f77a7c649314fa3fb4ec69894b075468697320697320612074657374206d65737361676521"

func TestGenerateKey(t *testing.T) {
	keyPair, err := GenerateKey()
	if err != nil {
		t.Error(err)
	}
	fmt.Printf("Private: %s\nPublic: %s\n", keyPair.PrivateKey, keyPair.PublicKey)
}

func TestSignMessage(t *testing.T) {
	signedMessage, err := Sign(testPrivateKey, testMessage)
	if err != nil {
		t.Error(err)
	}

	fmt.Printf("Signed Message: %s\n", signedMessage)
}

func TestSignMessageInvalidKey(t *testing.T) {
	_, err := Sign("INVALID KEY", testMessage)
	if err == nil {
		t.Error("Expected error got nil")
	}
}

func TestOpenMessage(t *testing.T) {
	message, err := Open(testPublicKey, testSignedMessage)

	if err != nil {
		t.Fatal(err)
	}

	if message != testMessage {
		t.Fatal("Message does not match")
	}

	fmt.Printf("Verified Message: %s\n", message)
}

func TestOpenMessageInvalidMessage(t *testing.T) {
	_, err := Open(testPublicKey, "INVALID MESSAGE")

	if err == nil {
		t.Fatal("No error found but error should occur")
	}
}

func TestOpenMessageInvalidMessageHex(t *testing.T) {
	_, err := Open(testPublicKey, "ABC123")

	if err == nil {
		t.Fatal("No error found but error should occur")
	}
}
