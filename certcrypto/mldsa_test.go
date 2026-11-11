//go:build go1.27

package certcrypto

import (
	"crypto/mldsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGeneratePrivateKey_mldsa(t *testing.T) {
	testCases := []struct {
		keyType  KeyType
		expected mldsa.Parameters
	}{
		{keyType: MLDSA44, expected: mldsa.MLDSA44()},
		{keyType: MLDSA65, expected: mldsa.MLDSA65()},
		{keyType: MLDSA87, expected: mldsa.MLDSA87()},
	}

	for _, test := range testCases {
		t.Run(test.keyType.String(), func(t *testing.T) {
			t.Parallel()

			key, err := GeneratePrivateKey(test.keyType)
			require.NoError(t, err)

			require.IsType(t, &mldsa.PrivateKey{}, key)
			assert.Equal(t, test.expected, key.(*mldsa.PrivateKey).PublicKey().Parameters())

			keyType, err := GetPrivateKeyType(key)
			require.NoError(t, err)

			assert.Equal(t, test.keyType, keyType)

			keyType, err = GetKeyType(key)
			require.NoError(t, err)

			assert.Equal(t, test.keyType, keyType)
		})
	}
}

func TestPEMEncode_mldsa(t *testing.T) {
	for _, keyType := range []KeyType{MLDSA44, MLDSA65, MLDSA87} {
		t.Run(keyType.String(), func(t *testing.T) {
			t.Parallel()

			privateKey, err := GeneratePrivateKey(keyType)
			require.NoError(t, err)

			data := PEMEncode(privateKey)
			require.NotNil(t, data)

			p, rest := pem.Decode(data)

			assert.Equal(t, "PRIVATE KEY", p.Type)
			assert.Empty(t, rest)
			assert.Empty(t, p.Headers)

			decoded, err := ParsePEMPrivateKey(data)
			require.NoError(t, err)

			require.IsType(t, &mldsa.PrivateKey{}, decoded)
			assert.True(t, decoded.(*mldsa.PrivateKey).Equal(privateKey))
		})
	}
}

func TestCreateCSR_mldsa(t *testing.T) {
	privateKey, err := GeneratePrivateKey(MLDSA44)
	require.NoError(t, err)

	der, err := CreateCSR(privateKey, CSROptions{SAN: []string{testDomain1}})
	require.NoError(t, err)

	csr, err := x509.ParseCertificateRequest(der)
	require.NoError(t, err)

	require.NoError(t, csr.CheckSignature())

	assert.Equal(t, []string{testDomain1}, csr.DNSNames)

	keyType, err := GetCSRKeyType(csr)
	require.NoError(t, err)

	assert.Equal(t, MLDSA44, keyType)
}

func TestToKeyType_mldsa(t *testing.T) {
	for _, expected := range []KeyType{MLDSA44, MLDSA65, MLDSA87} {
		t.Run(expected.String(), func(t *testing.T) {
			t.Parallel()

			keyType, err := ToKeyType(strings.ToLower(expected.String()))
			require.NoError(t, err)

			assert.Equal(t, expected, keyType)
			assert.True(t, IsSupported(keyType))
			assert.Contains(t, AllKeyTypes(), keyType)
		})
	}
}
