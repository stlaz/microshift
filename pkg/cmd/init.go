/*
Copyright © 2021 MicroShift Contributors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"net"
	"path/filepath"

	"k8s.io/apiserver/pkg/authentication/user"
	ctrl "k8s.io/kubernetes/pkg/controlplane"

	"github.com/openshift/microshift/pkg/config"
	"github.com/openshift/microshift/pkg/util"
	"github.com/openshift/microshift/pkg/util/cryptomaterial"
)

func initAll(cfg *config.MicroshiftConfig) error {
	// create CA and keys
	clusterTrustBundlePEM, certChains, err := initCerts(cfg)
	if err != nil {
		return err
	}
	// create kubeconfig for kube-scheduler, kubelet,controller-manager
	if err := initKubeconfig(cfg, clusterTrustBundlePEM, certChains); err != nil {
		return err
	}

	return nil
}

func loadCA(cfg *config.MicroshiftConfig) error {
	return util.LoadRootCA(filepath.Join(cfg.DataDir, "/certs/ca-bundle"), "ca-bundle.crt", "ca-bundle.key")
}

func initCerts(cfg *config.MicroshiftConfig) ([]byte, *cryptomaterial.CertificateChains, error) {
	_, svcNet, err := net.ParseCIDR(cfg.Cluster.ServiceCIDR)
	if err != nil {
		return nil, nil, err
	}

	_, apiServerServiceIP, err := ctrl.ServiceIPRange(*svcNet)
	if err != nil {
		return nil, nil, err
	}

	certsDir := cryptomaterial.CertsDirectory(cfg.DataDir)
	// store root CA for all
	//TODO generate ca bundles for each component
	clusterTrustBundlePEM, _, err := util.StoreRootCA("https://kubernetes.svc", filepath.Join(certsDir, "/ca-bundle"),
		"ca-bundle.crt", "ca-bundle.key",
		[]string{"https://kubernetes.svc"})

	if err != nil {
		return nil, nil, err
	}

	certChains, err := cryptomaterial.NewCertificateChains(
		// ------------------------------
		// CLIENT CERTIFICATE SIGNERS
		// ------------------------------

		// kube-control-plane-signer
		cryptomaterial.NewCertificateSigner(
			"kube-control-plane-signer",
			cryptomaterial.KubeControlPlaneSignerCertDir(certsDir),
			cryptomaterial.KubeControlPlaneSignerCAValidityDays,
		).WithClientCertificates(
			&cryptomaterial.ClientCertificateSigningRequestInfo{
				CertificateSigningRequestInfo: cryptomaterial.CertificateSigningRequestInfo{
					Name:         "kube-controller-manager",
					ValidityDays: cryptomaterial.ClientCertValidityDays,
				},
				UserInfo: &user.DefaultInfo{Name: "system:kube-controller-manager"},
			},
			&cryptomaterial.ClientCertificateSigningRequestInfo{
				CertificateSigningRequestInfo: cryptomaterial.CertificateSigningRequestInfo{
					Name:         "kube-scheduler",
					ValidityDays: cryptomaterial.ClientCertValidityDays,
				},
				UserInfo: &user.DefaultInfo{Name: "system:kube-scheduler"},
			}),

		// kube-apiserver-to-kubelet-signer
		cryptomaterial.NewCertificateSigner(
			"kube-apiserver-to-kubelet-signer",
			cryptomaterial.KubeAPIServerToKubeletSignerCertDir(certsDir),
			cryptomaterial.KubeAPIServerToKubeletCAValidityDays,
		).WithClientCertificates(
			&cryptomaterial.ClientCertificateSigningRequestInfo{
				CertificateSigningRequestInfo: cryptomaterial.CertificateSigningRequestInfo{
					Name:         "kube-apiserver-to-kubelet-client",
					ValidityDays: cryptomaterial.ClientCertValidityDays,
				},
				UserInfo: &user.DefaultInfo{Name: "system:kube-apiserver", Groups: []string{"kube-master"}},
			}),

		// admin-kubeconfig-signer
		cryptomaterial.NewCertificateSigner(
			"admin-kubeconfig-signer",
			cryptomaterial.AdminKubeconfigSignerDir(certsDir),
			cryptomaterial.AdminKubeconfigCAValidityDays,
		).WithClientCertificates(
			&cryptomaterial.ClientCertificateSigningRequestInfo{
				CertificateSigningRequestInfo: cryptomaterial.CertificateSigningRequestInfo{
					Name:         "admin-kubeconfig-client",
					ValidityDays: cryptomaterial.AdminKubeconfigClientCertValidityDays,
				},
				UserInfo: &user.DefaultInfo{Name: "system:admin", Groups: []string{"system:masters"}},
			}),

		// kubelet + CSR signing chain
		cryptomaterial.NewCertificateSigner(
			"kubelet-signer",
			cryptomaterial.KubeletCSRSignerSignerCertDir(certsDir),
			cryptomaterial.KubeControllerManagerCSRSignerSignerCAValidityDays,
		).WithSubCAs(
			cryptomaterial.NewCertificateSigner(
				"kube-csr-signer",
				cryptomaterial.CSRSignerCertDir(certsDir),
				cryptomaterial.KubeControllerManagerCSRSignerCAValidityDays,
			).WithClientCertificates(
				&cryptomaterial.ClientCertificateSigningRequestInfo{
					CertificateSigningRequestInfo: cryptomaterial.CertificateSigningRequestInfo{
						Name:         "kubelet-client",
						ValidityDays: cryptomaterial.ClientCertValidityDays,
					},
					// userinfo per https://kubernetes.io/docs/reference/access-authn-authz/node/#overview
					UserInfo: &user.DefaultInfo{Name: "system:node:" + cfg.NodeName, Groups: []string{"system:nodes"}},
				},
			).WithServingCertificates(
				&cryptomaterial.ServingCertificateSigningRequestInfo{
					CertificateSigningRequestInfo: cryptomaterial.CertificateSigningRequestInfo{
						Name:         "kubelet-server",
						ValidityDays: cryptomaterial.ServingCertValidityDays,
					},
					Hostnames: []string{cfg.NodeName, cfg.NodeIP},
				},
			),
		),
		cryptomaterial.NewCertificateSigner(
			"aggregator-signer",
			cryptomaterial.AggregatorSignerDir(certsDir),
			cryptomaterial.AggregatorFrontProxySignerCAValidityDays,
		).WithClientCertificates(
			&cryptomaterial.ClientCertificateSigningRequestInfo{
				CertificateSigningRequestInfo: cryptomaterial.CertificateSigningRequestInfo{
					Name:         "aggregator-client",
					ValidityDays: cryptomaterial.ClientCertValidityDays,
				},
				UserInfo: &user.DefaultInfo{Name: "system:openshift-aggregator"},
			},
		),

		//------------------------------
		// SERVING CERTIFICATE SIGNERS
		//------------------------------
		cryptomaterial.NewCertificateSigner(
			"service-ca",
			cryptomaterial.ServiceCADir(certsDir),
			cryptomaterial.ServiceCAValidityDays,
		).WithServingCertificates(
			&cryptomaterial.ServingCertificateSigningRequestInfo{
				CertificateSigningRequestInfo: cryptomaterial.CertificateSigningRequestInfo{
					Name:         "route-controller-manager-serving",
					ValidityDays: cryptomaterial.ServiceCAServingCertValidityDays,
				},
				Hostnames: []string{
					"route-controller-manager.openshift-route-controller-manager.svc",
					"route-controller-manager.openshift-route-controller-manager.svc.cluster.local",
				},
			},
		),

		//------------------------------
		// 	ETCD CERTIFICATE SIGNER
		//------------------------------
		cryptomaterial.NewCertificateSigner(
			"etcd-signer",
			cryptomaterial.EtcdSignerDir(certsDir),
			cryptomaterial.EtcdSignerCAValidityDays,
		).WithClientCertificates(
			&cryptomaterial.ClientCertificateSigningRequestInfo{
				CertificateSigningRequestInfo: cryptomaterial.CertificateSigningRequestInfo{
					Name:         "apiserver-etcd-client",
					ValidityDays: 10 * 365,
				},
				UserInfo: &user.DefaultInfo{Name: "etcd", Groups: []string{"etcd"}},
			},
		).WithPeerCertificiates(
			&cryptomaterial.PeerCertificateSigningRequestInfo{
				CertificateSigningRequestInfo: cryptomaterial.CertificateSigningRequestInfo{
					Name:         "etcd-peer",
					ValidityDays: 3 * 365,
				},
				UserInfo:  &user.DefaultInfo{Name: "system:etcd-peer:etcd-client", Groups: []string{"system:etcd-peers"}},
				Hostnames: []string{"localhost", cfg.NodeIP, "127.0.0.1", cfg.NodeName},
			},
			&cryptomaterial.PeerCertificateSigningRequestInfo{
				CertificateSigningRequestInfo: cryptomaterial.CertificateSigningRequestInfo{
					Name:         "etcd-serving",
					ValidityDays: 3 * 365,
				},
				UserInfo:  &user.DefaultInfo{Name: "system:etcd-server:etcd-client", Groups: []string{"system:etcd-servers"}},
				Hostnames: []string{"localhost", "127.0.0.1", cfg.NodeIP, cfg.NodeName},
			},
		),
	).WithCABundle(
		cryptomaterial.TotalClientCABundlePath(certsDir),
		"kube-control-plane-signer",
		"kube-apiserver-to-kubelet-signer",
		"admin-kubeconfig-signer",
		"kubelet-signer",
		// kube-csr-signer is being added below
	).WithCABundle(
		cryptomaterial.KubeletClientCAPath(certsDir),
		"kube-control-plane-signer",
		"kube-apiserver-to-kubelet-signer",
		"admin-kubeconfig-signer",
		"kubelet-signer",
		// kube-csr-signer is being added below
	).Complete()

	if err != nil {
		return nil, nil, err
	}

	csrSignerCAPEM, err := certChains.GetSigner("kubelet-signer", "kube-csr-signer").GetSignerCertPEM()
	if err != nil {
		return nil, nil, err
	}

	if err := cryptomaterial.AddToKubeletClientCABundle(certsDir, csrSignerCAPEM); err != nil {
		return nil, nil, err
	}

	if err := cryptomaterial.AddToTotalClientCABundle(certsDir, csrSignerCAPEM); err != nil {
		return nil, nil, err
	}

	// kube-apiserver
	if err := util.GenCerts("kube-apiserver", filepath.Join(cfg.DataDir, "/certs/kube-apiserver/secrets/service-network-serving-certkey"),
		"tls.crt", "tls.key",
		[]string{"kube-apiserver", cfg.NodeIP, cfg.NodeName, "127.0.0.1", "kubernetes.default.svc", "kubernetes.default", "kubernetes",
			"localhost",
			apiServerServiceIP.String()}); err != nil {
		return nil, nil, err
	}
	if err := util.GenKeys(filepath.Join(cfg.DataDir, "/resources/kube-apiserver/secrets/service-account-key"),
		"service-account.crt", "service-account.key"); err != nil {
		return nil, nil, err
	}

	return clusterTrustBundlePEM, certChains, nil
}

func initKubeconfig(
	cfg *config.MicroshiftConfig,
	clusterTrustBundlePEM []byte,
	certChains *cryptomaterial.CertificateChains,
) error {

	adminKubeconfigCertPEM, adminKubeconfigKeyPEM, err := certChains.GetCertKey("admin-kubeconfig-signer", "admin-kubeconfig-client")
	if err != nil {
		return err
	}
	if err := util.KubeConfigWithClientCerts(
		cfg.KubeConfigPath(config.KubeAdmin),
		cfg.Cluster.URL,
		clusterTrustBundlePEM,
		adminKubeconfigCertPEM,
		adminKubeconfigKeyPEM,
	); err != nil {
		return err
	}

	kcmCertPEM, kcmKeyPEM, err := certChains.GetCertKey("kube-control-plane-signer", "kube-controller-manager")
	if err != nil {
		return err
	}
	if err := util.KubeConfigWithClientCerts(
		cfg.KubeConfigPath(config.KubeControllerManager),
		cfg.Cluster.URL,
		clusterTrustBundlePEM,
		kcmCertPEM,
		kcmKeyPEM,
	); err != nil {
		return err
	}

	schedulerCertPEM, schedulerKeyPEM, err := certChains.GetCertKey("kube-control-plane-signer", "kube-scheduler")
	if err != nil {
		return err
	}
	if err := util.KubeConfigWithClientCerts(
		cfg.KubeConfigPath(config.KubeScheduler),
		cfg.Cluster.URL,
		clusterTrustBundlePEM,
		schedulerCertPEM, schedulerKeyPEM,
	); err != nil {
		return err
	}

	kubeletCertPEM, kubeletKeyPEM, err := certChains.GetCertKey("kubelet-signer", "kube-csr-signer", "kubelet-client")
	if err != nil {
		return err
	}
	if err := util.KubeConfigWithClientCerts(
		cfg.KubeConfigPath(config.Kubelet),
		cfg.Cluster.URL,
		clusterTrustBundlePEM,
		kubeletCertPEM, kubeletKeyPEM,
	); err != nil {
		return err
	}
	return nil
}
