# MicroShift Development Environment on RHEL 8
The development environment bootstrap and configuration procedures are automated as described in the [Automating Development Environment Setup](./devenv_rhel8_auto.md) document.
It is recommended to review the current document and use the automation instructions to create and configure the environment.

## Create Development Virtual Machine
Start by downloading the RHEL 8.6 or above ISO image from the https://developers.redhat.com/products/rhel/download location. 
> RHEL 9.x operating system is not currently supported.

### Creating VM
Create a RHEL 8 virtual machine with 2 cores, 4096MB of RAM and 50GB of storage. 
> Visual Studio Code may consume around 2GB of RAM. For running the IDE on the development virtual machine, it is recommended to allocate at least 6144MB of RAM in total.

Move the ISO image to `/var/lib/libvirt/images` directory and run the following command to create a virtual machine.
```bash
sudo dnf install -y libvirt virt-manager virt-viewer libvirt-client qemu-kvm qemu-img

VMNAME="microshift-dev"
sudo -b bash -c " \
cd /var/lib/libvirt/images/ && \
virt-install \
    --name ${VMNAME} \
    --vcpus 2 \
    --memory 4096 \
    --disk path=./${VMNAME}.qcow2,size=50 \
    --network network=default,model=virtio \
    --os-type generic \
    --events on_reboot=restart \
    --cdrom ./rhel-8.6-$(uname -i)-boot.iso \
"
```

In the OS installation wizard, set the following options:
- Root password and `microshift` administrator user
- Select "Installation Destination"
    - Under "Storage Configuration" sub-section, select "Custom" radial button
    - Select "Done" to open a window for configuring partitions
    - Under "New Red Hat Enterprise Linux 8.x Installation", click "Click here to create them automatically"
    - Select the root partition (`/`)
        - On the right side of the menu, set "Desired Capacity" to `40 GiB`
        - Click "Update Settings" button
        > This will preserve the rest of the allocatable storage for dynamically provisioned logical volumes. The MicroShift default CSI provisioner requires at least 1GB of unallocated storage in the volume group. Adjust the capacity as desired.
    - Click "Done" button.
    - At the "Summary of Changes" window, select "Accept Changes"

- Connect network card and set the hostname (i.e. `microshift-dev.localdomain`)
- Register the system with Red Hat using your credentials (toggle off Red Hat Insights connection)
- In the Software Selection, select Minimal Install base environment and toggle on Headless Management to enable Cockpit

Click on Begin Installation and wait until the OS installation is complete.

### Configuring VM
Log into the virtual machine using SSH with the `microshift` user credentials.

Run the following commands to configure SUDO, upgrade the system, install basic dependencies and enable remote Cockpit console.
```bash
echo -e 'microshift\tALL=(ALL)\tNOPASSWD: ALL' | sudo tee /etc/sudoers.d/microshift
sudo dnf update -y
sudo dnf install -y git cockpit make gcc selinux-policy-devel rpm-build bash-completion
sudo systemctl enable --now cockpit.socket
export GO_VER=1.18.7; curl -L -o go${GO_VER}.linux-amd64.tar.gz https://go.dev/dl/go${GO_VER}.linux-amd64.tar.gz &&
    sudo rm -rf /usr/local/go${GO_VER} && \
    sudo mkdir -p /usr/local/go${GO_VER} && \
    sudo tar -C /usr/local/go${GO_VER} -xzf go${GO_VER}.linux-amd64.tar.gz --strip-components 1 && \
    sudo rm -rfv /usr/local/bin/{go,gofmt}
    sudo ln --symbolic /usr/local/go1.18.7/bin/go /usr/local/go1.18.7/bin/gofmt /usr/local/bin/ && \
    rm -rfv go${GO_VER}.linux-amd64.tar.gz
```
You should now be able to access the VM Cockpit console using `https://<vm_ip>:9090` URL.

## Build MicroShift 
Log into the development virtual machine with the `microshift` user credentials.
Clone the repository to be used for building various artifacts.
```bash
git clone https://github.com/openshift/microshift.git ~/microshift
cd ~/microshift
```

### Executable
Run `make` command in the top-level directory. If necessary, add `DEBUG=true` argument to the `make` command for building a binary with debug symbols.
```bash
make
```
The artifact of the build is the `microshift` executable file located in the `_output/bin` directory.

### RPM Packages
Run make command with the `rpm` or `srpm` argument in the top-level directory. 
```bash
make rpm
make srpm
```

The artifacts of the build are located in the `_output/rpmbuild` directory.
```bash
$ cd ~/microshift/ && find . -name \*.rpm
./_output/rpmbuild/RPMS/x86_64/microshift-4.12.0-nightly_20220908132255_152_g4267d5d1.el8.x86_64.rpm
./_output/rpmbuild/RPMS/x86_64/microshift-networking-4.12.0-nightly_20220908132255_152_g4267d5d1.el8.x86_64.rpm
./_output/rpmbuild/RPMS/noarch/microshift-selinux-4.12.0-nightly_20220908132255_152_g4267d5d1.el8.noarch.rpm
./_output/rpmbuild/SRPMS/microshift-4.12.0-nightly_20220908132255_152_g4267d5d1.el8.src.rpm
```

## Run MicroShift Executable
Log into the development virtual machine with the `microshift` user credentials.

### Runtime Prerequisites
When working a MicroShift based on a pre-release _minor_ version `Y` of OpenShift, the corresponding RPM repo `rhocp-4.$Y-for-rhel-8-$ARCH-rpms` won't be available yet. In that case, use the `Y-1` version.

> If you have VPN access to the Red Hat build systems, you can add the corresponding puddle repo.
>
> ```bash
> sudo tee /etc/yum.repos.d/internal-rhocp-4.12-for-rhel-8-rpms.repo >/dev/null <<EOF
> [internal-rhocp-4.12-for-rhel-8-rpms]
> name=Puddle of the rhocp-4.12 RPMs for RHEL8
> baseurl=http://download.lab.bos.redhat.com/rcm-guest/puddles/RHAOS/plashets/4.12-el8/building/\$basearch/os/
> enabled=1
> gpgcheck=0
> skip_if_unavailable=1
> EOF
> ```

Enable the needed repositories and install the MicroShift RPM packages. This procedure pulls in the required package dependencies, also installing the necessary configuration files and `systemd` units.

```bash
sudo subscription-manager repos \
    --enable rhocp-4.11-for-rhel-8-$(uname -i)-rpms \
    --enable fast-datapath-for-rhel-8-$(uname -i)-rpms
sudo dnf localinstall -y ~/microshift/_output/rpmbuild/RPMS/*/*.rpm
```

Download the OpenShift pull secret from the https://console.redhat.com/openshift/downloads#tool-pull-secret page. Copy it to `/etc/crio/openshift-pull-secret` and update its file permissions so `CRI-O` can use it when fetching container images.
```bash
sudo chmod 600 /etc/crio/openshift-pull-secret
```

### Installing Clients
Run the following commands to install `oc` and `kubectl` utilities.
```bash
sudo dnf install -y openshift-clients
```

### Configuring MicroShift
MicroShift requires system configuration updates before it can be run. These updates include `CRI-O`, networking and file system customizations.

> If a firewall is enabled, follow the instructions in the [Firewall Configuration](./howto_firewall.md) document to apply the mandatory settings.

The MicroShift service is not enabled or started by default. Start the service once to trigger the initialization sequence of all the dependencies.
```bash
sudo systemctl enable crio
sudo systemctl start microshift
```

> The `CRI-O` service is started automatically by `systemd` as one of MicroShift dependencies. Enabling the `CRI-O` service is necessary to allow running MicroShift as a standalone executable.

Wait until all the pods are up and running.
```bash
watch sudo $(which oc) --kubeconfig /var/lib/microshift/resources/kubeadmin/kubeconfig get pods -A
```

Finalize the procedure by stopping the MicroShift service and cleaning up its images and configuration data.
```
echo 1 | ~/microshift/hack/cleanup.sh
```

It should now be possible to run a standalone MicroShift executable file as presented in the next section.

### Running MicroShift
Run the MicroShift executable file in the background using the following command.
```bash
nohup sudo ~/microshift/_output/bin/microshift run >> /tmp/microshift.log &
```
Examine the `/tmp/microshift.log` log file to ensure a successful startup.

> An alternative way of running MicroShift is to update `/usr/bin/microshift` file and restart the service. The logs would then be accessible by running the `journalctl -xu microshift` command.
> ```bash
> sudo cp -f ~/microshift/_output_/bin/microshift /usr/bin/microshift
> sudo systemctl restart microshift
> ```

Copy `kubeconfig` to the default location that can be accessed without the administrator privilege.
```bash
mkdir -p ~/.kube/
sudo cat /var/lib/microshift/resources/kubeadmin/kubeconfig > ~/.kube/config
```

Verify that the MicroShift is running.
```bash
oc get cs
watch oc get pods -A
```

### Stopping MicroShift
Run the following command to stop the MicroShift process and make sure it is shut down by examining its log file.
```bash
sudo kill microshift && sleep 3
tail -3 /tmp/microshift.log 
```
> If MicroShift is running as a service, it is necessary to execute the `sudo systemctl stop microshift` command to shut it down and review the output of the `journalctl -xu microshift` command to verify the service termination.

This command only stops the MicroShift process. To perform the full cleanup including `CRI-O`, MicroShift and OVN caches, run the following script.
```bash
echo 1 | ~/microshift/hack/cleanup.sh
```
> The full cleanup does not remove OVS configuration applied by the MicroShift service initialization sequence.
> Run the `sudo /usr/bin/configure-ovs.sh` command to revert to the original network settings.

## Quick Development and Edge Testing Cycle
During the development cycle, it is practical to build and run MicroShift executable as demonstrated in the [Build MicroShift](#build-microshift) and [Run MicroShift Executable](#run-microshift-executable) sections above. However, it is also necessary to have a convenient technique for testing the system in a setup resembling the production environment. Such an environment can be created in a virtual machine as described in the [Install MicroShift on RHEL for Edge](./rhel4edge_iso.md) document. 

Once a RHEL for Edge virtual machine is created, it is running a version of MicroShift with the latest changes. When MicroShift code is updated and the executable file is rebuilt with the new changes, the updates need to be installed on RHEL for Edge OS.

Since it takes a long time to create a new RHEL for Edge installer ISO and deploy it on a virtual machine, the remainder of this section describes a simple technique for replacing the MicroShift executable file on an existing RHEL for Edge OS installation.

### Configuring ostree
Log into the RHEL for Edge machine using `redhat:redhat` credentials. Run the following command for configuring the ostree to allow transient overlays on top of the /usr directory.
```bash
sudo rpm-ostree usroverlay
```

This would enable a development mode where users can overwrite `/usr` directory contents. Note that all changes will be discarded on reboot.

### Updating MicroShift Executable
Log into the development virtual machine with the `microshift` user credentials. 

It is recommended to update the local `/etc/hosts` to resolve the `microshift-edge` host name. Also, generate local SSH keys and allow the `microshift` user to run SSH commands without the password on the RHEL for Edge machine.
```bash
ssh-keygen
ssh-copy-id redhat@microshift-edge
```

Rebuild the MicroShift executable as described in the [Build MicroShift](#build-microshift) section and run the following commands to copy, cleanup, replace and restart the new service on the RHEL for Edge system.
```bash
scp ~/microshift/_output/bin/microshift redhat@microshift-edge:
ssh redhat@microshift-edge ' \
    echo 1 | /usr/bin/cleanup-all-microshift-data && \
    sudo cp ~redhat/microshift /usr/bin/microshift && \
    sudo systemctl enable microshift --now && \
    echo Done '
```

## Profile MicroShift
Golang [pprof](https://pkg.go.dev/net/http/pprof) is a useful tool for serving runtime profiling data via an HTTP server in the format expected by the `pprof` visualization tool.
> Runtime profiling is disabled by default and it should not be enabled in the production environment.

Run MicroShift with `--debug.pprof=true` command line argument to serve runtime profiling data on port `29500`.

```
nohup sudo ~/microshift/microshift run --debug.pprof=true >> /tmp/microshift.log &
```

> It may be necessary to configure your firewall for accessing the `pprof` HTTP server remotely.
>```
>sudo firewall-cmd --permanent --add-port=29500/tcp
>sudo firewall-cmd --reload
>```

Runtime profiling data can now be accessed from the command line as described in the [pprof](https://pkg.go.dev/net/http/pprof) documentation. As an example, the following command can be used to look at the heap profile.

```
PPROF_ADDR=microshift-dev:29500
go tool pprof http://${PPROF_ADDR}/debug/pprof/heap
```

To view all the available profiles, open the `http://microshift-dev:29500/debug/pprof` URL in your browser.

![All pprof profiles](./images/devenv_pprof.png)
