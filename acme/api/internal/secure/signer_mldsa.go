//go:build go1.27

package secure

import (
	"crypto"
	"crypto/mldsa"

	"github.com/go-jose/go-jose/v4"
)

func mldsaSignatureAlgorithm(pubKey crypto.PublicKey) jose.SignatureAlgorithm {
	k, ok := pubKey.(*mldsa.PublicKey)
	if !ok {
		return ""
	}

	switch k.Parameters() {
	case mldsa.MLDSA44():
		return jose.MLDSA44
	case mldsa.MLDSA65():
		return jose.MLDSA65
	case mldsa.MLDSA87():
		return jose.MLDSA87
	}

	return ""
}
