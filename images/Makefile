PATHS=/lustre/workspace/archcommon/ubuntu_qemu_image
IMAGES=ubuntu.qcow2 vmlinuz-5.0.0-8-generic initrd.img-5.0.0-8-generic
#Assume only one of the paths is valid
IMGHOME:= $(wildcard $(PATHS))

all-images:$(IMAGES)

$(IMAGES):
	test ! -h $@ && ln -s $(IMGHOME)/$@

clean:
	rm -f $(IMAGES)
