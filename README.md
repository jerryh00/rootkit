# Introduction

This is a kernel rootkit demo. It hides itself and specified modules by
hooking module show functions.

# Software requirements:

1. Linaro aarch64-linux-gnu toolchain.
2. QEMU
3. buildroot
4. linux kernel source

Follow the instructions in this post to setup the environment(install
toolchain, install qemu, build kernel and rootfs):
http://www.bennee.com/~alex/blog/2014/05/09/running-linux-in-qemus-aarch64-system-emulation-mode/

# Compiling the project:

Modify KERNEL_BUILD in Makefile to the kernel build directory

build the rootkit module by running:

make

# Running the project:

In kernel build dir, run(be sure to modify path=xxx to your rootkit directory):
qemu-system-aarch64 -machine virt -cpu cortex-a57 -machine type=virt -nographic -smp 1 -m 512 -kernel arch/arm64/boot/Image --append "console=ttyAMA0" -fsdev local,id=r,path=path-to-rootkit-dir,security_model=none -device virtio-9p-device,fsdev=r,mount_tag=r

After the kernel boots, login with root, then run:
mount -t 9p -o trans=virtio r /mnt

cd /mnt

insmod hello.ko

lsmod # check that hello module is loaded

insmod rk.ko

lsmod # both modules are hidden

# Quitting:

ctrl-a x
