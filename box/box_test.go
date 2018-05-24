package box

import (
	"fmt"
	"testing"
)

const testMessage = "This is a test message!"
const testSharedKey = "8b614617f09e54f8c20fd552a3096478a0bd265cda45758d4b0a4449f6d55108"
const testSealedMessage = "e79c70f5b2338b165dbe7c8392bf6b51261d2aa13d5607dbaf7aea7d75e7226eb3867d7fcd67fceae22743085f8f79c98df0a561b4d4f9d088a9f0708dfedc"

func TestGenerateKey(t *testing.T) {
	keyPair, err := GenerateKey()
	if err != nil {
		t.Error(err)
	}
	fmt.Printf("Private: %s\nPublic: %s\n", keyPair.PrivateKey, keyPair.PublicKey)
}

func TestSealMessage(t *testing.T) {
	signedMessage, err := Seal(testSharedKey, testMessage)
	if err != nil {
		t.Error(err)
	}

	fmt.Printf("Sealed Message: %s\n", signedMessage)
}

func TestSealMessageInvalidKey(t *testing.T) {
	_, err := Seal("INVALID KEY", testMessage)
	if err == nil {
		t.Error("Expected error got nil")
	}
}

func TestStringTo32Bytes(t *testing.T) {
	_, err := hexStringTo32Bytes("INVALID STRING")
	if err == nil {
		t.Errorf("Got no error expeted: %s", err.Error())
	}
}

func TestOpenMessage(t *testing.T) {
	message, err := Open(testSharedKey, testSealedMessage)

	if err != nil {
		t.Fatal(err)
	}

	if message != testMessage {
		t.Fatal("Message does not match")
	}

	fmt.Printf("Verified Message: %s\n", message)
}

func TestOpenMessageInvalidMessage(t *testing.T) {
	_, err := Open(testSharedKey, "INVALID MESSAGE")

	if err == nil {
		t.Fatal("No error found but error should occur")
	}
}

func TestOpenMessageInvalidMessageHex(t *testing.T) {
	_, err := Open(testSharedKey, "ABC123")

	if err == nil {
		t.Fatal("No error found but error should occur")
	}
}

func TestSealOpenMessage(t *testing.T) {
	senderKeyPair, _ := GenerateKey()
	recipientKeyPair, _ := GenerateKey()

	fmt.Printf("Sender Key: %s\n", senderKeyPair)
	fmt.Printf("Recipient Key : %s\n", recipientKeyPair)

	senderSharedKey, _ := SharedKey(recipientKeyPair.PublicKey, senderKeyPair.PrivateKey)
	recipientSharedKey, _ := SharedKey(senderKeyPair.PublicKey, recipientKeyPair.PrivateKey)

	fmt.Printf("Sender Shared Key: %s\n", senderSharedKey)
	fmt.Printf("Recipient Shared Key : %s\n", recipientSharedKey)

	encryptedMessage, err := Seal(senderSharedKey, testMessage)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("Encrypted Message: %s\n", encryptedMessage)

	decryptedMessage, err := Open(senderSharedKey, encryptedMessage)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("Decrypted Message: %s\n", decryptedMessage)

}
