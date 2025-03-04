package components

import (
	"path/filepath"

	"github.com/openshift/microshift/pkg/assets"
	"github.com/openshift/microshift/pkg/config"
	"k8s.io/klog/v2"
)

func startOVNKubernetes(cfg *config.MicroshiftConfig, kubeconfigPath string) error {
	var (
		ns = []string{
			"components/ovn/namespace.yaml",
		}
		sa = []string{
			"components/ovn/node/serviceaccount.yaml",
			"components/ovn/master/serviceaccount.yaml",
		}
		r = []string{
			"components/ovn/role.yaml",
		}
		rb = []string{
			"components/ovn/rolebinding.yaml",
		}
		cr = []string{
			"components/ovn/clusterrole.yaml",
		}
		crb = []string{
			"components/ovn/clusterrolebinding.yaml",
		}
		cm = []string{
			"components/ovn/configmap.yaml",
		}
		apps = []string{
			"components/ovn/master/daemonset.yaml",
			"components/ovn/node/daemonset.yaml",
		}
	)

	if err := assets.ApplyNamespaces(ns, kubeconfigPath); err != nil {
		klog.Warningf("Failed to apply ns %v: %v", ns, err)
		return err
	}
	if err := assets.ApplyServiceAccounts(sa, kubeconfigPath); err != nil {
		klog.Warningf("Failed to apply serviceAccount %v %v", sa, err)
		return err
	}
	if err := assets.ApplyRoles(r, kubeconfigPath); err != nil {
		klog.Warningf("Failed to apply role %v: %v", r, err)
		return err
	}
	if err := assets.ApplyRoleBindings(rb, kubeconfigPath); err != nil {
		klog.Warningf("Failed to apply rolebinding %v: %v", rb, err)
		return err
	}
	if err := assets.ApplyClusterRoles(cr, kubeconfigPath); err != nil {
		klog.Warningf("Failed to apply clusterRole %v %v", cr, err)
		return err
	}
	if err := assets.ApplyClusterRoleBindings(crb, kubeconfigPath); err != nil {
		klog.Warningf("Failed to apply clusterRoleBinding %v %v", crb, err)
		return err
	}
	extraParams := assets.RenderParams{
		"KubeconfigPath": kubeconfigPath,
		"KubeconfigDir":  filepath.Join(cfg.DataDir, "/resources/kubeadmin"),
	}
	if err := assets.ApplyConfigMaps(cm, renderTemplate, renderParamsFromConfig(cfg, extraParams), kubeconfigPath); err != nil {
		klog.Warningf("Failed to apply configMap %v %v", cm, err)
		return err
	}
	if err := assets.ApplyDaemonSets(apps, renderTemplate, renderParamsFromConfig(cfg, extraParams), kubeconfigPath); err != nil {
		klog.Warningf("Failed to apply apps %v %v", apps, err)
		return err
	}
	return nil
}
