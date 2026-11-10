package certcrypto

import (
	"bytes"
	"crypto"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testDomain1 = "lego.example"
	testDomain2 = "a.lego.example"
	testDomain3 = "b.lego.example"
	testDomain4 = "c.lego.example"
)

func TestGeneratePrivateKey(t *testing.T) {
	key, err := GeneratePrivateKey(RSA2048)
	require.NoError(t, err, "Error generating private key")

	assert.NotNil(t, key)
}

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
		})
	}
}

func TestGenerateCSR(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err, "Error generating private key")

	type expected struct {
		len   int
		error bool
	}

	testCases := []struct {
		desc       string
		privateKey crypto.Signer
		opts       CSROptions
		expected   expected
	}{
		{
			desc:       "without SAN (nil)",
			privateKey: privateKey,
			opts: CSROptions{
				Domain:     testDomain1,
				MustStaple: true,
			},
			expected: expected{len: 382},
		},
		{
			desc:       "without SAN (empty)",
			privateKey: privateKey,
			opts: CSROptions{
				Domain:     testDomain1,
				SAN:        []string{},
				MustStaple: true,
			},
			expected: expected{len: 382},
		},
		{
			desc:       "with SAN",
			privateKey: privateKey,
			opts: CSROptions{
				Domain:     testDomain1,
				SAN:        []string{testDomain2, testDomain3, testDomain4},
				MustStaple: true,
			},
			expected: expected{len: 442},
		},
		{
			desc:       "no domain",
			privateKey: privateKey,
			opts: CSROptions{
				Domain:     "",
				MustStaple: true,
			},
			expected: expected{len: 359},
		},
		{
			desc:       "no domain with SAN",
			privateKey: privateKey,
			opts: CSROptions{
				Domain:     "",
				SAN:        []string{testDomain2, testDomain3, testDomain4},
				MustStaple: true,
			},
			expected: expected{len: 419},
		},
		{
			desc:       "private key nil",
			privateKey: nil,
			opts: CSROptions{
				Domain:     testDomain1,
				MustStaple: true,
			},
			expected: expected{error: true},
		},
		{
			desc:       "with email addresses",
			privateKey: privateKey,
			opts: CSROptions{
				Domain:         "example.com",
				SAN:            []string{"example.org"},
				EmailAddresses: []string{"foo@example.com", "bar@example.com"},
			},
			expected: expected{len: 421},
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			csr, err := CreateCSR(test.privateKey, test.opts)

			if test.expected.error {
				require.Error(t, err)
			} else {
				require.NoError(t, err, "Error generating CSR")

				assert.NotEmpty(t, csr)
				assert.Len(t, csr, test.expected.len)
			}
		})
	}
}

func TestPEMEncode(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err, "Error generating private key")

	data := PEMEncode(key)
	require.NotNil(t, data)

	p, rest := pem.Decode(data)

	assert.Equal(t, "PRIVATE KEY", p.Type)
	assert.Empty(t, rest)
	assert.Empty(t, p.Headers)
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

func TestParsePEMCertificate(t *testing.T) {
	privateKey, err := GeneratePrivateKey(RSA2048)
	require.NoError(t, err, "Error generating private key")

	expiration := time.Now().Add(365).Round(time.Second)
	certBytes, err := generateDerCert(privateKey.(*rsa.PrivateKey), expiration, "test.com", nil)
	require.NoError(t, err, "Error generating cert")

	buf := bytes.NewBufferString("TestingRSAIsSoMuchFun")

	// Some random string should return an error.
	cert, err := ParsePEMCertificate(buf.Bytes())
	require.Errorf(t, err, "returned %v", cert)

	// A DER encoded certificate should return an error.
	_, err = ParsePEMCertificate(certBytes)
	require.Error(t, err, "Expected to return an error for DER certificates")

	// A PEM encoded certificate should work ok.
	pemCert := PEMEncode(DERCertificateBytes(certBytes))
	cert, err = ParsePEMCertificate(pemCert)
	require.NoError(t, err)

	assert.Equal(t, expiration.UTC(), cert.NotAfter)
}

func TestParsePEMPrivateKey(t *testing.T) {
	privateKey, err := GeneratePrivateKey(RSA2048)
	require.NoError(t, err, "Error generating private key")

	pemPrivateKey := PEMEncode(privateKey)

	// Decoding a key should work and create an identical RSA key to the original,
	// ignoring precomputed values.
	decoded, err := ParsePEMPrivateKey(pemPrivateKey)
	require.NoError(t, err)

	decodedRsaPrivateKey := decoded.(*rsa.PrivateKey)
	require.True(t, decodedRsaPrivateKey.Equal(privateKey))

	// Decoding a PEM block that doesn't contain a private key should error
	_, err = ParsePEMPrivateKey(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE"}))
	require.Errorf(t, err, "Expected to return an error for non-private key input")

	// Decoding a PEM block that doesn't actually contain a key should error
	_, err = ParsePEMPrivateKey(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY"}))
	require.Errorf(t, err, "Expected to return an error for empty input")

	// Decoding non-PEM input should return an error
	_, err = ParsePEMPrivateKey([]byte("This is not PEM"))
	require.Errorf(t, err, "Expected to return an error for non-PEM input")
}
