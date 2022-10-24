package cryptomaterial

import (
	"crypto/x509"
	"encoding/pem"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/openshift/library-go/pkg/crypto"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/util/diff"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authentication/user"
)

func Test_certificateSigner_Complete(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name       string
		testSigner *certificateSigner
		wantCerts  []string
		wantSubCAs []string
		wantErr    bool
	}{
		{
			name: "general test",
			testSigner: NewCertificateSigner("test-signer-signer", filepath.Join(tmpDir, "generalTest"), 1).
				WithClientCertificates(
					&ClientCertificateSigningRequestInfo{
						CertificateSigningRequestInfo: CertificateSigningRequestInfo{
							Name:         "test-client",
							ValidityDays: 1,
						},
						UserInfo: &user.DefaultInfo{Name: "test-user", Groups: []string{"test-group1", "test-group2"}},
					},
					&ClientCertificateSigningRequestInfo{
						CertificateSigningRequestInfo: CertificateSigningRequestInfo{
							Name:         "test-client2",
							ValidityDays: 1,
						},
						UserInfo: &user.DefaultInfo{Name: "test-user", Groups: []string{"test-group1", "test-group2"}},
					},
				).WithServingCertificates(
				&ServingCertificateSigningRequestInfo{
					CertificateSigningRequestInfo: CertificateSigningRequestInfo{
						Name:         "test-server",
						ValidityDays: 1,
					},
					Hostnames: []string{"localhost", "127.0.0.1"},
				},
			).
				WithSubCAs(NewCertificateSigner("test-signer", filepath.Join(tmpDir, "test-signer"), 1)),
			wantCerts:  []string{"test-client", "test-client2", "test-server"},
			wantSubCAs: []string{"test-signer"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.testSigner.Complete()
			if (err != nil) != tt.wantErr {
				t.Errorf("certificateSigner.Complete() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotCertNames := got.GetCertNames(); !reflect.DeepEqual(gotCertNames, tt.wantCerts) {
				t.Errorf("the completed signer cert names = %v, want %v", gotCertNames, tt.wantCerts)
			}
			if gotSubCANames := got.GetSubCANames(); !reflect.DeepEqual(gotSubCANames, tt.wantSubCAs) {
				t.Errorf("the completed signer sub-CA names = %v, want %v", gotSubCANames, tt.wantSubCAs)

			}
		})
	}
}

func Test_certificateChains_Complete(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name            string
		testChains      *certificateChains
		testClientPaths map[string]user.Info
		testServerPaths map[string]sets.String
		wantSigners     []string
		wantErr         bool
	}{
		{
			name: "general test",
			testChains: NewCertificateChains(
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
					),
				NewCertificateSigner("test-signer2", filepath.Join(tmpDir, "test-signer2"), 1).
					WithServingCertificates(&ServingCertificateSigningRequestInfo{
						CertificateSigningRequestInfo: CertificateSigningRequestInfo{
							Name:         "test-server1",
							ValidityDays: 1,
						},
						Hostnames: []string{"somewhere.over.the.rainbow", "bluebirds.fly"},
					}),
			),
			wantSigners: []string{"test-signer1", "test-signer2"},
			testClientPaths: map[string]user.Info{
				"test-signer1/test-client1": &user.DefaultInfo{Name: "test-user", Groups: []string{"test-group1", "test-group2"}},
				"test-signer1/test-client2": &user.DefaultInfo{Name: "test-user2"},
				"test-signer1/test-client":  nil,
			},
			testServerPaths: map[string]sets.String{
				"test-signer2/test-server1": sets.NewString("somewhere.over.the.rainbow", "bluebirds.fly"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cs := tt.testChains
			got, err := cs.Complete()
			if (err != nil) != tt.wantErr {
				t.Errorf("certificateChains.Complete() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotSignerNames := got.GetSignerNames(); !reflect.DeepEqual(gotSignerNames, tt.wantSigners) {
				t.Errorf("certificateChains.Complete() = %v, want %v", gotSignerNames, tt.wantSigners)
			}

			for path, expectedInfo := range tt.testClientPaths {
				gotPEM, _, err := got.GetCertKey(breakTestCertPath(path)...)

				if expectedInfo == nil {
					if err == nil {
						t.Errorf("expected certificate to not be found at path %q, but got %s", path, gotPEM)
					}
					continue
				} else {
					require.NoError(t, err, "failed to retrieve cert/key pair from the certificate chains")
				}

				gotCert := pemToCert(t, gotPEM)

				if cn := gotCert.Subject.CommonName; cn != expectedInfo.GetName() {
					t.Errorf("expected certificate CN at path %q to be %q, but it is %q", path, expectedInfo.GetName(), cn)
				}

				if orgs := gotCert.Subject.Organization; !reflect.DeepEqual(orgs, expectedInfo.GetGroups()) {
					t.Errorf("expected certificate O at path %q to be %v, but it is %v", path, expectedInfo.GetGroups(), orgs)
				}
			}

			for path, expectedHostnames := range tt.testServerPaths {
				gotPEM, _, err := got.GetCertKey(breakTestCertPath(path)...)

				if expectedHostnames == nil {
					if err == nil {
						t.Errorf("expected certificate to not be found at path %q, but got %s", path, gotPEM)
					}
					continue
				} else {
					require.NoError(t, err, "failed to retrieve cert/key pair from the certificate chains")
				}

				gotCert := pemToCert(t, gotPEM)

				if cn := gotCert.Subject.CommonName; cn != expectedHostnames.List()[0] {
					t.Errorf("expected certificate CN at path %q to be %q, but it is %q", path, expectedHostnames.List()[0], cn)
				}

				expectedIPs, expectedDNSes := crypto.IPAddressesDNSNames(expectedHostnames.List())
				if !equality.Semantic.DeepEqual(gotCert.IPAddresses, expectedIPs) || !equality.Semantic.DeepEqual(gotCert.DNSNames, expectedDNSes) {
					t.Errorf("extected certificate at path %q to have IPs %v and DNS names %v, but got %v and %v", path, expectedIPs, expectedDNSes, gotCert.IPAddresses, gotCert.DNSNames)
				}
			}
		})
	}
}

func pemToCert(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()

	pemBlock, _ := pem.Decode(certPEM)
	require.NotNil(t, pemBlock, "failed to decode certificate PEM")

	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	require.NoError(t, err, "failed to parse certificate PEM into a certificate")

	return cert
}

func breakTestCertPath(testPath string) []string {
	return strings.Split(testPath, "/")
}

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
