obj-m += rk.o
obj-m += hello.o

rk-objs := hook.o stub.o module.o hide.o
hello-objs := hello_main.o

ARCH=arm64
CROSS_COMPILE=aarch64-linux-gnu-

KERNEL_BUILD=~/linux

all:
	make ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) -C ${KERNEL_BUILD} M=$(PWD) modules

clean:
	make ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) -C  ${KERNEL_BUILD} M=$(PWD) clean
