//go:build go1.27

package e2e

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/go-acme/lego/v5/e2e/loader"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMLDSA_Run(t *testing.T) {
	testCases := []certcrypto.KeyType{
		certcrypto.MLDSA44,
		certcrypto.MLDSA65,
		certcrypto.MLDSA87,
	}

	for _, keyType := range testCases {
		t.Run(keyType.String(), func(t *testing.T) {
			loader.CleanLegoFiles(t.Context())

			err := load.RunLego(t.Context(),
				"run",
				"-m", testEmail1,
				"--accept-tos",
				"-s", caDirectory,
				"-d", testDomain1,
				"--key-type", keyType.String(),
				"--http",
				"--http.address", ":5002",
			)
			require.NoError(t, err)

			data, err := os.ReadFile(filepath.FromSlash(".lego/certificates/" + testDomain1 + ".crt"))
			require.NoError(t, err)

			cert, err := certcrypto.ParsePEMCertificate(data)
			require.NoError(t, err)

			certKeyType, err := certcrypto.GetCertificateKeyType(cert)
			require.NoError(t, err)

			assert.Equal(t, keyType, certKeyType)
		})
	}
}
