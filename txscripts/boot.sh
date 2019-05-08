../build/aarch64-softmmu/qemu-system-aarch64 \
                -m 4096M -M virt,gic-version=3 -cpu max \
                -global virtio-blk-device.scsi=off \
                -device virtio-scsi-device,id=scsi \
                -drive file=../images/ubuntu.qcow2,snapshot=on,id=coreimg,cache=unsafe,if=none,format=qcow2 \
                -device scsi-hd,drive=coreimg -netdev user,id=unet,hostfwd=tcp::2223-:22 \
                -device virtio-net-device,netdev=unet -kernel ../images/vmlinuz-5.0.0-8-generic -initrd ../images/initrd.img-5.0.0-8-generic -display sdl -nographic \
                -append "root=/dev/sda2 lpj=34920500 notsc nowatchdog rcupdate.rcu_cpu_stall_suppress=1" \
                -plugin "file=../plugins/perfsim-log/perfsim-log.so"
