## Edwards-curve Digital Signature Algorithm (EdDSA)

### Introduction

  EdDSA is a signature scheme based on the elliptic curve cryptography.
  It is a deterministic signature scheme, which means that the same
  message will always produce the same signature.

  EdDSA is a key-pair based scheme, which means that the private key
  is not stored in the signature.
  
### Implementation

  EdDSA is implemented in the [Ed25519](https://ed25519.cr.yp.to/)
  and [Ed448](https://ed448.io/) algorithms.
  
### Usage

  EdDSA is used to sign messages with a private key and verify
  signatures with a public key.
  
### Example

  The following example shows how to sign and verify a message.

```go
import (
  "crypto/ed25519"
  "crypto/rand"
  "fmt"
)

func main() {
  // Generate a new key pair.
  privateKey, publicKey, err := ed25519.GenerateKey(rand.Reader)
  if err != nil {
  	panic(err)
  }

  // Sign a message.
  message := []byte("Hello, world!")
  signature := ed25519.Sign(privateKey, message)

  // Verify the signature.
  fmt.Println(ed25519.Verify(publicKey, message, signature))
}
```