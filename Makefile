VNAME=$(shell cat VERSION)


all:
	cd libreassure && make
	cd tool && make

.PHONY: clean dist 



dist:
	make clean
	mkdir -p /tmp/$(VNAME)
	find . | grep -v '/\.' | cpio -dump /tmp/$(VNAME)/
	cd /tmp && rm -f $(VNAME).tar.gz && \
		tar -c $(VNAME) | gzip > $(VNAME).tar.gz
	mv /tmp/$(VNAME).tar.gz .
	rm -rf /tmp/$(VNAME)


clean:
	cd tests && make clean
	cd tool && make clean
	cd libreassure && make clean

