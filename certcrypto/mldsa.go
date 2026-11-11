//go:build go1.27

package certcrypto

import (
	"crypto"
	"crypto/mldsa"
	"fmt"
)

const (
	MLDSA44 = KeyType("MLDSA44")
	MLDSA65 = KeyType("MLDSA65")
	MLDSA87 = KeyType("MLDSA87")
)

// mldsaKeyTypes returns the ML-DSA key types supported by this build.
func mldsaKeyTypes() []KeyType {
	return []KeyType{MLDSA44, MLDSA65, MLDSA87}
}

// generateMLDSAKey generates an ML-DSA private key. It returns an error if
// keyType is not an ML-DSA key type.
func generateMLDSAKey(keyType KeyType) (crypto.Signer, error) {
	switch keyType {
	case MLDSA44:
		return mldsa.GenerateKey(mldsa.MLDSA44())
	case MLDSA65:
		return mldsa.GenerateKey(mldsa.MLDSA65())
	case MLDSA87:
		return mldsa.GenerateKey(mldsa.MLDSA87())
	}

	return nil, fmt.Errorf("invalid KeyType: %s", keyType)
}

// isMLDSAPrivateKey reports whether key is an ML-DSA private key.
func isMLDSAPrivateKey(key any) bool {
	_, ok := key.(*mldsa.PrivateKey)

	return ok
}

// getMLDSAKeyType gets the key type of an ML-DSA key.
// It returns an error if key is not an ML-DSA key.
func getMLDSAKeyType(key any) (KeyType, error) {
	var params mldsa.Parameters

	switch k := key.(type) {
	case *mldsa.PublicKey:
		params = k.Parameters()
	case *mldsa.PrivateKey:
		params = k.PublicKey().Parameters()
	default:
		return "", fmt.Errorf("unsupported key type: %T", key)
	}

	switch params {
	case mldsa.MLDSA44():
		return MLDSA44, nil
	case mldsa.MLDSA65():
		return MLDSA65, nil
	case mldsa.MLDSA87():
		return MLDSA87, nil
	default:
		return "", fmt.Errorf("unsupported ML-DSA parameters: %s", params)
	}
}
