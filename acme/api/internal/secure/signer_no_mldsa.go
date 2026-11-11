//go:build !go1.27

package secure

import (
	"crypto"

	"github.com/go-jose/go-jose/v4"
)

// ML-DSA requires Go 1.27 or later.
func mldsaSignatureAlgorithm(_ crypto.PublicKey) jose.SignatureAlgorithm {
	return ""
}
