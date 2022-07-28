program = "netflow-analyzer.1.0_amd64"
ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

netflow-analyzer: 
	gcc -pthread -o netflow-analyzer main.c 
		

deb: netflow-analyzer.deb clean
	
netflow-analyzer.deb:
	mkdir -p $(program)/usr/local/bin
	mkdir $(program)/DEBIAN
	cp $(ROOT_DIR)/DEBIAN/control $(ROOT_DIR)/$(program)/DEBIAN/
	cp $(ROOT_DIR)/netflow-analyzer $(ROOT_DIR)/$(program)/usr/local/bin/
	dpkg-deb --build --root-owner-group $(program)
	
clean:
	rm -r $(program)
