package certcrypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// NOTE(ldez) RSA4096 and RSA8192 are not tested because the key generation is very slow.
func TestGetPrivateKeyType(t *testing.T) {
	mustGenerateKey := func(c crypto.Signer, err error) crypto.Signer {
		require.NoError(t, err)
		return c
	}

	testCases := []struct {
		desc     string
		key      crypto.Signer
		expected KeyType
	}{
		{
			desc:     "ECDSA256",
			key:      mustGenerateKey(ecdsa.GenerateKey(elliptic.P256(), rand.Reader)),
			expected: EC256,
		},
		{
			desc:     "ECDSA384",
			key:      mustGenerateKey(ecdsa.GenerateKey(elliptic.P384(), rand.Reader)),
			expected: EC384,
		},
		{
			desc:     "RSA2048",
			key:      mustGenerateKey(rsa.GenerateKey(rand.Reader, 2048)),
			expected: RSA2048,
		},
		{
			desc:     "RSA3072",
			key:      mustGenerateKey(rsa.GenerateKey(rand.Reader, 3072)),
			expected: RSA3072,
		},
		{
			desc:     "MLDSA44",
			key:      mustGenerateKey(mldsa.GenerateKey(mldsa.MLDSA44())),
			expected: MLDSA44,
		},
		{
			desc:     "MLDSA65",
			key:      mustGenerateKey(mldsa.GenerateKey(mldsa.MLDSA65())),
			expected: MLDSA65,
		},
		{
			desc:     "MLDSA87",
			key:      mustGenerateKey(mldsa.GenerateKey(mldsa.MLDSA87())),
			expected: MLDSA87,
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			keyType, err := GetPrivateKeyType(test.key)
			require.NoError(t, err)

			assert.Equal(t, test.expected, keyType)
		})
	}
}

func TestGetPrivateKeyType_error(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	require.NoError(t, err)

	_, err = GetPrivateKeyType(key)
	require.EqualError(t, err, "unsupported ECDSA curve: 224")
}

func TestGetCertificateKeyType(t *testing.T) {
	path := "./testdata/cert-p256.pem"

	data, err := os.ReadFile(path)
	require.NoError(t, err)

	cert, err := ParsePEMCertificate(data)
	require.NoError(t, err)

	keyType, err := GetCertificateKeyType(cert)
	require.NoError(t, err)

	assert.Equal(t, EC256, keyType)
}

func TestGetCertificateKeyType_error(t *testing.T) {
	path := "./testdata/cert-p224.pem"

	data, err := os.ReadFile(path)
	require.NoError(t, err)

	cert, err := ParsePEMCertificate(data)
	require.NoError(t, err)

	_, err = GetCertificateKeyType(cert)
	require.EqualError(t, err, "unsupported ECDSA curve: 224")
}

func TestToKeyType(t *testing.T) {
	for _, expected := range AllKeyTypes() {
		t.Run(expected.String(), func(t *testing.T) {
			t.Parallel()

			keyType, err := ToKeyType(strings.ToLower(expected.String()))
			require.NoError(t, err)

			assert.Equal(t, expected, keyType)
			assert.True(t, IsSupported(keyType))
		})
	}
}

func TestToKeyType_error(t *testing.T) {
	_, err := ToKeyType("MLDSA42")
	require.EqualError(t, err, "unsupported key type: MLDSA42")
}
