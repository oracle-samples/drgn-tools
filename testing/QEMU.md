# Qemu Build on OL8

Unfortunately QEMU on OL8 seems to be missing several useful tools for emulation
and sharing data:

- NVME emulation
- Block devices mapped to host

To make it easier to use QEMU features to test drgn-tools, we build the latest
qemu and install it to the system. Here's the steps I used:

```bash
mkdir ~/work && cd ~/work

sudo yum-config-manager --enable ol8_codeready_builder
sudo yum-config-manager --enable ol8_developer_EPEL

sudo yum remove dtrace  # conflicted with a systemtap dependency

# https://wiki.qemu.org/Hosts/Linux#Fedora_Linux_.2F_Debian_GNU_Linux_.2F_Ubuntu_Linux_.2F_Linux_Mint_distributions
sudo yum install git glib2-devel libfdt-devel pixman-devel zlib-devel bzip2 ninja-build python3
sudo yum install libaio-devel libcap-ng-devel libiscsi-devel capstone-devel \
                 gtk3-devel  vte291-devel ncurses-devel \
                 libseccomp-devel nettle-devel libattr-devel libjpeg-devel \
                 brlapi-devel libgcrypt-devel lzo-devel snappy-devel \
                 librdmacm-devel libibverbs-devel cyrus-sasl-devel libpng-devel \
                 libuuid-devel pulseaudio-libs-devel curl-devel libssh-devel \
                 systemtap-sdt-devel libusbx-devel
# Removed libsdl2-devel from the above^

# For usermode networking
sudo yum install libslirp-devel

wget https://download.qemu.org/qemu-7.2.0.tar.xz
tar xvJf qemu-7.2.0.tar.xz
mkdir build
cd build

../qemu-7.2.0/configure --target-list=x86_64-softmmu
make -j20
sudo make install
```
