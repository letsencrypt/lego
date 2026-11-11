//go:build !go1.27

package certcrypto

import (
	"crypto"
	"fmt"
)

func mldsaKeyTypes() []KeyType {
	return nil
}

func generateMLDSAKey(keyType KeyType) (crypto.Signer, error) {
	return nil, fmt.Errorf("invalid KeyType: %s", keyType)
}

func isMLDSAPrivateKey(_ any) bool {
	return false
}

func getMLDSAKeyType(key any) (KeyType, error) {
	return "", fmt.Errorf("unsupported key type: %T", key)
}
