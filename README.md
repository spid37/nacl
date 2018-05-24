# go nacl wrapper

Wrapper for golang.org/x/crypto/nacl/box and golang.org/x/crypto/nacl/sign to return hex string

## bind for mobile

```bash
gomobile bind -target ios -o build/nacl.framework github.com/spid37/go/nacl/box github.com/spid37/go/nacl/sign
```

```bash
gomobile bind -target android -o build/nacl.aar github.com/spid37/go/nacl/box github.com/spid37/go/nacl/sign
```

## Example

### sign message

```go
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
	fmt.Printf("Opened message: %s\n", message)
}
```

```
Got the Private Key: f8ec910599b737488633ba72d6c4f98ed696888578b7e33ab112b573bf7ecb6be7db80cb066660bead8c3c270dc43aaed56eba641aed3647c5764b00d5c977c7
Got the PublicKey Key: e7db80cb066660bead8c3c270dc43aaed56eba641aed3647c5764b00d5c977c7
Signed the message: cf7100c7520dae1fdb2a9b8daa41bd34fe548e01776f19e61116e4e6062bc4659996f83eea181e7de613748b0e6e119932f83eefc3f4bdc5ecc131b1bb7c0c01546869732069732061206d657373616765
Open the message: This is a message
```
