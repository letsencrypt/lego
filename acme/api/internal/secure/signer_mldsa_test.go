//go:build go1.27

package secure

import (
	"crypto/mldsa"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSigner_SignContent_mldsa(t *testing.T) {
	privKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)

	signer := NewSigner(privKey, "https://foo.example/kid")

	content, err := signer.SignContent(&MockNonceSource{}, "https://foo.example", []byte("{}"))
	require.NoError(t, err)

	check(t, content)
}
