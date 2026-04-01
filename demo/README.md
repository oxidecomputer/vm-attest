This repo hosts code to demonstrate use of the vm-attest API.

## executables

The `src/` directory contains source code for 3 executables. These programs can
be used to test / demonstrate various components in this architecture.
Each are documented in [src/bin/README.md](src/bin/README.md).

## test vm

`demo-vm.sh` in the root of the project directory creates a bootable Debian
virtual disk image. It uses a `debootstrap` to build the base image and then
applies modifications to:

- make the image bootable from a read-only device
- install `cloud-init` to pick up config when booting in the rack
- setup `overlayroot` to setup overlayfs on / backed by a tmpfs get ephemeral
  writable disk (required by `cloud-init`)
- build and copy the [vm-instance](src/bin/vm-instance.rs) and
  [appraiser](src/bin/appraiser.rs) tools into the image
- generate and install test data: certs, keys, logs, and reference integrity
  measurements

This script also generates a tarball w/ the test data that's been installed in
the virtual disk image. These are intended to be used as input to a
`propolis-standalone` configuration file using the `mock` attest backend.

This script manipulates `nbd` devices, bind mounts etc which require root
permissions: You should read the script before you run it.

### dependencies

debootstrap
qemu-img
qemu-nbd
parted
mkfs (vfat & ext4)
blkid
pki-playground
attest-mock
tar
fstrim
gzip

## tool selection

There are a lot of ways to build Linux systems in virtual disks. Choosing
`debootstrap` means that we're limiting ourselves to Debian. The complexity in
the other available options (Nix/NixOS, OpenEmbedded etc) serves a purpose and
by going a different route we must work within certain constraints. The work
associated with setting up a more flexible tool is deferred till necessary.
