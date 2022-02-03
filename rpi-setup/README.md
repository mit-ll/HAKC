# RPI Setup
 
## Assembly
- Follow CanaKit instructions for assembly

## Environment setup
- `export RPI_IMG=20210413_raspi_4_bullseye.img.xz`
- `export RPI_URL=https://raspi.debian.net/verified/$RPI_IMG`

## Installing Debian firmware and root fs
- `wget $RPI_URL`
- Use `lsblk` to check which drive is the SD Card
  - We use use `/dev/sdCHANGEME` for that device
- `xzcat $RPI_IMG | dd of=/dev/sdCHANGEME bs=64k 
  oflag=dsync status=progress`
- Unmount the SD card, and boot debian on the Pi
- On the Pi, `apt update && apt install apache2`
- Shutdown the Pi

## Building Kernel
- `export BUILD_TYPE=exp-build`
- `export BUILD_ARGS="ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- LLVM=1 CC=clang HOSTCC=clang"`  
- `make $BUILD_ARGS LOCALVERSION=$BUILD_TYPE defconfig`
- Run `make $BUILD_ARGS LOCALVERSION=$BUILD_TYPE menuconfig` to adjust configs as 
  necessary.
- Need to set the following configs:
```
CONFIG_PAC_MTE_COMPART=y
CONFIG_PAC_MTE_COMPART_ALLOW_FAILED=n
CONFIG_PAC_MTE_COMPART_SIGN_PTR=y
CONFIG_PAC_MTE_COMPART_IPV6=y
CONFIG_PAC_MTE_COMPART_NF_TABLES=y
CONFIG_PAC_MTE_EVAL_CODEGEN=y
CONFIG_IPV6=m
CONFIG_DEBUG_INFO_SPLIT=y
```
NB: `CONFIG_IPV6` is built in by default, and must be made to a module instead.

- To build, run `make $BUILD_ARGS LOCALVERSION=$BUILD_TYPE -j$(nproc)`

## Installing new Image, modules, and Device Trees 
- Do the following to mount:
  - Use `lsblk` to check which partitions are `RASPIFIRM` and `RASPIROOT`
    - `RASPIFIRM` is the boot partition, `RASPIROOT` is the root partition
- Run `sudo mount /dev/sdCHANGEME_1 <path-to-ext4-rpi-root-fs>` to mount boot 
  partition
- Run `sudo mount /dev/sdCHANGEME_2 <path-to-fat32-rpi-boot-image>` to mount 
  root partition
- Run `sudo make $BUILD_ARGS LOCALVERSION=$BUILD_TYPE
  INSTALL_MOD_PATH=<path-to-ext4-rpi-root-fs> modules_install`
  - Make note of the build number that is the last output text, `<BUILD ID>`
- To copy image to rpi boot image, run `sudo cp 
  <path-to-build>/arch/arm64/boot/Image.gz 
  <path-to-fat32-rpi-boot-image>/exp-build.img`

## Generate kernel specific initramfs

- SAFELY unmount the SD card
  - This can take a while while the filesystems sync
- Boot the Pi
- After login, `mkinitramfs -v -o /boot/initrd.exp-build.img <BUILD ID>`
- Power off the Pi
- Mount the SD card
- `sudo cp <path-to-ext4-rpi-root-fs>/boot/initrd.exp-build.img <path-to-fat32-rpi-boot-image>`

## Set RPI kernel to boot
- You can specify which kernel you want to boot for the RPI in `<path-to-fat32-rpi-boot-image>/config.txt`
- Set the config variables one per line `kernel=exp-build.img` 
  `initramfs=initrd.exp-build.img`
- Comment out the existing config variables
- SAFELY unmount the SD Card
- Boot the kernel

## Using the serial console
- Ensure that `console=ttyS0,115200 kgdboc=ttyS0,115200 plymouth.enable=0` 
  is added to `cmdline.txt`
- Ensure that `corefreq=250` is added to `config.txt`
- Follow the directions at https://www.programmersought.com/article/46311659317/
- Ensure your user is part of the group that has write access to `/dev/ttyUSB0`
- `minicom -b 115200 -o -D /dev/ttyUSB0`

## Assign a static IPv6 address
- Open `/etc/network/interfaces.d/eth0`
- Append the following and save:
```
iface eth0 inet6 static
	address fdf2:5e8e:743d::43
	gateway fdf2:5e8e:743d::1
	netmask 64
```
- Assign a static IPv6 address to your laptop
  - It will likely involve adding something like the above to a similar file 
    on your machine
- Restart the Pi, and connect the laptop and the Pi with an ethernet cable.    

## Emulate with QEMU
- `mkdir linux-envs; cd linux-envs`
- `wget $RPI_URL`
  - If the URL cannot be found, find the latest image on https://raspi.debian.net 
- `dd if=/dev/null of=disk.img bs=1M seek=10240`
  - This creates a 10GB file named `disk.img`
- `xzcat $RPI_IMG | dd of=disk.img conv=notrunc status=progress`
- `sudo partx -a -v disk.img`
  - This will output that it is using a loop device, such as `/dev/loop0`. 
    That's the device we will continue to use, so replace accordingly.
- `mkdir host-mount`
- `sudo mount /dev/loop0p1 host-mount`
- `cp host-mount/initrd.img* .`
- `cp host-mount/vmlinuz-5.10* .`
- `qemu-system-aarch64 -M virt,mte=on -m 4096 -cpu max
  -drive format=raw,file=disk.img -nographic
  -append "root=/dev/vda2 net.ifaces=0 rootwait"
  -initrd initrd.img-5.10.0-5-arm64
  -kernel vmlinuz-5.10.0-5-arm64`
  - The initial run of `qemu` resizes the root filesystem partition to use 
    the full remaining space in the disk image, and is necessary to install 
    new modules.
  - The username is `root` with no password, for military grade security  
- `apt update && apt install apache2`
  - If DNS is not resolving names, append `nameserver 8.8.8.8` to
    `/etc/resolv.conf`
- `poweroff`
- `sudo umount host-mount`
- `sudo mount /dev/loop0p2 host-mount`
- `pushd /path/to/kernel/build; sudo make <ARGS> 
  INSTALL_MOD_PATH=/path/to/host-mount modules_install`
  - Make note of the build number that is outputted last
- `popd`
- `sudo umount host-mount`
- `sudo mount /dev/loop0p1 host-mount`
- Start qemu
- `mkinitramfs -v -o /boot/firmware/initrd.pmc-build.img <BUILD NUMBER>`
- `poweroff`
- `sudo umount host-mount`
- `sudo mount /dev/loop0p1 host-mount`  
- `cp host-mount/initrd.pmc-build.img .`
- `qemu-system-aarch64 -M virt,mte=on -m 4096 -cpu max
  -drive format=raw,file=disk.img -nographic
  -device virtio-net-pci,netdev=net0
  -netdev user,id=net0,hostfwd=tcp::8032-:80
  -append "$(cat host-mount/cmdline.txt)"
  -initrd initrd.pmc-build.img
  -kernel /path/to/Image.gz`
