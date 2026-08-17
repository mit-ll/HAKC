PMCPass
=======

PMCPass is an LLVM pass that attempts to instrument as much of the Linux kernel
as possible with the PAC-MTE checks.

Prerequisites
-------------
* Binutils 2.33.1 or greater 
* aarch64-linux-gnu-gcc
* LLVM version 11, including llvm-ar, llvm-objcopy, lld, llvm-as

To Build LLVM Pass
------------------

1. Determine your LLMV version and install location for LLVM top directory: `clang --version`
   * On Ubuntu 20.10, the version is `11.0.0` and the LLVM top directory is
   `/usr/lib/llvm-11`
1. `cd PMC-Pass`
1. `mkdir build`
1. `cd build`
1. `cmake -DLT_LLVM_INSTALL_DIR=<LLVM Install dir> -DPMC_LLVM_VERSION=<LLVM
version> ..`
1. `cmake --build .`

To Use while compiling the Linux kernel
---------------------------------------

1. `cd MTE-kernel`
1. `mkdir scripts/pac-mte`
1. `ln -s $(realpath ../PMC-Pass/build/lib/libPMCPass.so) scripts/pac-mte`
1. `export BUILD_TYPE=pmc-build && mkdir $BUILD_TYPE`
1. `cp ../packet-filtering/nftables_kernel_config_mte $BUILD_TYPE/.config`
1. `make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- LLVM=1 CC=clang
HOSTCC=clang O=$BUILD_TYPE LOCALVERSION=$BUILD_TYPE -j$(nproc)`

To boot PMC Protected kernel
----------------------------

1. Build QEMU from latest main branch to get MTE support
1. Follow the `Emulate with QEMU` directions in rpi-setup/README.md
