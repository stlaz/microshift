# Getting Started with MicroShift

> **Disclaimer**<br>
> This page describes an opinionated setup to facilitate a quick bootstrap of MicroShift in a virtual environment for **experimentation-only** purpose.
> See [Install MicroShift on RHEL for Edge](./docs/rhel4edge_iso.md) for more information on setting up a production-grade system with MicroShift.

The remainder of this document describes how to install a virtual machine running RHEL 8.6 operating system and an **experimental version** of MicroShift from the [@redhat-et/microshift-testing](https://copr.fedorainfracloud.org/coprs/g/redhat-et/microshift-testing) `copr` repository.

## Prerequisites

Log into the hypervisor machine using your user credentials.

Run the following command to install the necessary components for the [libvirt](https://libvirt.org/) virtualization platform and its [QEMU KVM](https://libvirt.org/drvqemu.html) hypervisor driver.
> **Note for Other Virtualization Platform Users** <br>
> Implement the virtual machine creation guidelines from [Bootstrap MicroShift](#bootstrap-microshift) using your virtualization platform and apply one of the following configuration steps:
> * When creating a virtual machine, pass the `inst.ks=...` boot option pointing to the [microshift-starter.ks](https://raw.githubusercontent.com/openshift/microshift/main/docs/config/microshift-starter.ks) kickstart file
> * After creating a virtual machine, manually execute the configuration steps from the [microshift-starter.ks](https://raw.githubusercontent.com/openshift/microshift/main/docs/config/microshift-starter.ks) kickstart file

```bash
sudo dnf install -y libvirt virt-manager virt-viewer libvirt-client qemu-kvm qemu-img
```

Download the [Red Hat Enterprise Linux 8.6 DVD ISO](https://developers.redhat.com/content-gateway/file/rhel-8.6-x86_64-dvd.iso) image for the x86_64 architecture from [Red Hat Developer](https://developers.redhat.com/products/rhel/download) site and copy the file to the `/var/lib/libvirt/images` directory.
> Other architectures, versions or flavors of operating systems are not supported. For this setup, only use the RHEL 8.6 DVD image for x86_64 architecture.

Download the OpenShift pull secret from the https://console.redhat.com/openshift/downloads#tool-pull-secret page and save it into the `~/.pull-secret.json` file.

## Bootstrap MicroShift

Log into the hypervisor machine using your user credentials.

Run the following commands to initiate the creation process of the `microshift-starter` virtual machine with 2 CPU cores, 2GB RAM and 20GB storage.

```bash
VMNAME=microshift-starter
DVDISO=/var/lib/libvirt/images/rhel-8.6-x86_64-dvd.iso
KICKSTART=https://raw.githubusercontent.com/openshift/microshift/main/docs/config/microshift-starter.ks

sudo -b bash -c " \
cd /var/lib/libvirt/images && \
virt-install \
    --name ${VMNAME} \
    --vcpus 2 \
    --memory 2048 \
    --disk path=./${VMNAME}.qcow2,size=20 \
    --network network=default,model=virtio \
    --events on_reboot=restart \
    --location ${DVDISO} \
    --extra-args \"inst.ks=${KICKSTART}\" \
"
```

Watch the OS console of the virtual machine to see the progress of the installation, waiting until the machine is rebooted and the login prompt appears.

## Access MicroShift

Log into the hypervisor machine using your user credentials.

Is it most convenient to access the MicroShift virtual machine using SSH. Run the following command to get the machine IP address and use it to remotely connect to the system.

```bash
sudo virsh domifaddr microshift-starter
```

First, copy your pull secret file to the MicroShift virtual machine using `redhat:redhat` credentials.

```bash
USHIFT_IP=192.168.122.2
scp ~/.pull-secret.json redhat@${USHIFT_IP}:
```

Log into the MicroShift virtual machine using `redhat:redhat` credentials. Run the following commands to configure `CRI-O` for using the pull secret and start the MicroShift service.

```bash
sudo cp ~redhat/.pull-secret.json /etc/crio/openshift-pull-secret
sudo systemctl enable --now microshift.service
```

Proceed by configuring MicroShift access for the `redhat` user account.

```bash
mkdir ~/.kube
sudo cat /var/lib/microshift/resources/kubeadmin/kubeconfig > ~/.kube/config
```

Finally, check if MicroShift is up and running by executing `oc` commands.
> When started for the first time, it may take a few minutes to download and initialize the container images used by MicroShift. On subsequent restarts, all the MicroShift services should take a few seconds to become available.

```bash
oc get cs
oc get pods -A
```
