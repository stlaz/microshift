package certchains

import (
	"crypto/x509"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"k8s.io/apimachinery/pkg/util/diff"
	"k8s.io/apiserver/pkg/authentication/user"
)

func TestCertificateChains_WalkChains(t *testing.T) {
	tmpDir := t.TempDir()

	testChains, err := NewCertificateChains(
		NewCertificateSigner("test-signer1", filepath.Join(tmpDir, "test-signer1"), 1).
			WithClientCertificates(&ClientCertificateSigningRequestInfo{
				CertificateSigningRequestInfo: CertificateSigningRequestInfo{
					Name:         "test-client1",
					ValidityDays: 1,
				},
				UserInfo: &user.DefaultInfo{Name: "test-user", Groups: []string{"test-group1", "test-group2"}},
			},
				&ClientCertificateSigningRequestInfo{
					CertificateSigningRequestInfo: CertificateSigningRequestInfo{
						Name:         "test-client2",
						ValidityDays: 1,
					},
					UserInfo: &user.DefaultInfo{Name: "test-user2"},
				},
			).WithServingCertificates(&ServingCertificateSigningRequestInfo{
			CertificateSigningRequestInfo: CertificateSigningRequestInfo{
				Name:         "test-signer1-server1",
				ValidityDays: 1,
			},
			Hostnames: []string{"behind.the.wardrobe.door"},
		}),
		NewCertificateSigner("test-signer2", filepath.Join(tmpDir, "test-signer2"), 1).
			WithServingCertificates(&ServingCertificateSigningRequestInfo{
				CertificateSigningRequestInfo: CertificateSigningRequestInfo{
					Name:         "test-server1",
					ValidityDays: 1,
				},
				Hostnames: []string{"somewhere.over.the.rainbow", "bluebirds.fly"},
			}),
		NewCertificateSigner("test-signer3", filepath.Join(tmpDir, "test-signer3"), 1).
			WithServingCertificates(&ServingCertificateSigningRequestInfo{
				CertificateSigningRequestInfo: CertificateSigningRequestInfo{
					Name:         "test-signer3-server1",
					ValidityDays: 1,
				},
				Hostnames: []string{"castle.brobdingnag"},
			}).
			WithSubCAs(NewCertificateSigner("test-signer3-subca1", filepath.Join(tmpDir, "test-signer3-subca1"), 1).
				WithClientCertificates(&ClientCertificateSigningRequestInfo{
					CertificateSigningRequestInfo: CertificateSigningRequestInfo{
						Name:         "test-client1",
						ValidityDays: 1,
					},
					UserInfo: &user.DefaultInfo{Name: "test-user", Groups: []string{"test-group1", "test-group2"}},
				}),
			).
			WithPeerCertificiates(&PeerCertificateSigningRequestInfo{
				CertificateSigningRequestInfo: CertificateSigningRequestInfo{
					Name:         "test-peer1",
					ValidityDays: 1,
				},
				UserInfo:  &user.DefaultInfo{Name: "test-user", Groups: []string{"test-group1"}},
				Hostnames: []string{"bring.a.towel"},
			}),
	).Complete()

	require.NoError(t, err)

	tests := []struct {
		name             string
		path             []string
		expectedSubjects string
		wantErr          bool
	}{
		{
			name:    "full tree traversal",
			path:    nil,
			wantErr: false,
			expectedSubjects: `
CN=test-signer1
	CN=test-user,O=test-group1+O=test-group2
	CN=test-user2
	CN=behind.the.wardrobe.door
CN=test-signer2
	CN=bluebirds.fly
CN=test-signer3
	CN=test-signer3-subca1
		CN=test-user,O=test-group1+O=test-group2
	CN=test-user,O=test-group1
	CN=castle.brobdingnag`,
		},
		{
			name:    "1-level signer",
			path:    []string{"test-signer1"},
			wantErr: false,
			expectedSubjects: `
CN=test-signer1
	CN=test-user,O=test-group1+O=test-group2
	CN=test-user2
	CN=behind.the.wardrobe.door`,
		},
		{
			name:    "signer w/ subca",
			path:    []string{"test-signer3"},
			wantErr: false,
			expectedSubjects: `
CN=test-signer3
	CN=test-signer3-subca1
		CN=test-user,O=test-group1+O=test-group2
	CN=test-user,O=test-group1
	CN=castle.brobdingnag`,
		},
		{
			name:    "signer/subca",
			path:    []string{"test-signer3", "test-signer3-subca1"},
			wantErr: false,
			expectedSubjects: `
	CN=test-signer3-subca1
		CN=test-user,O=test-group1+O=test-group2`,
		},
		{
			name:    "leaf cert",
			path:    []string{"test-signer2", "test-server1"},
			wantErr: false,
			expectedSubjects: `
	CN=bluebirds.fly`,
		},
		{
			name:    "leaf cert of subca",
			path:    []string{"test-signer3", "test-signer3-subca1", "test-client1"},
			wantErr: false,
			expectedSubjects: `
		CN=test-user,O=test-group1+O=test-group2`,
		},
		{
			name:    "nonexistent signer",
			path:    []string{"test-signer4"},
			wantErr: true,
		},
		{
			name:    "nonexistent intermediate signer",
			path:    []string{"test-signer3", "test-signer3-subca2", "test-client1"},
			wantErr: true,
		},
		{
			name:    "nonexistent leaf",
			path:    []string{"test-signer3", "test-signer3-subca1", "test-client2"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var subjects string
			walkFunc := func(path []string, c x509.Certificate) error {
				t.Helper()
				subjects += "\n" + strings.Repeat("\t", len(path)-1) + c.Subject.String()
				return nil
			}

			if err := testChains.WalkChains(tt.path, walkFunc); (err != nil) != tt.wantErr {
				t.Errorf("CertificateChains.WalkChains() error = %v, wantErr %v", err, tt.wantErr)
			}

			require.Equal(t, tt.expectedSubjects, subjects, "diff %s", diff.StringDiff(subjects, tt.expectedSubjects))
		})
	}
}
