# kernel code makefile

obj-m += common.o

all: clean
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

ins:
	sudo dmesg -c
	sudo insmod common.ko
	dmesg

rm:
	sudo rmmod common.ko
	sudo dmesg -c

test:
	sudo dmesg -c
	sudo insmod common.ko
	sudo rmmod common.ko
	dmesg
