INPUT_ROM_PATH := "rom/input.nds"
DOMAIN := "wc.skytemple.org"

default: rom/output.nds docker-images https-proxy/nas.crt

searchb-rs/target/release/searchb-rs:
	cd searchb-rs; cargo build --release

https-proxy/tls.pem.crt https-proxy/tls.pem.key:
	openssl req \
		-x509 -sha256 -nodes -days 3650 -newkey rsa:1024 \
		-keyout https-proxy/tls.pem.key \
		-out https-proxy/tls.pem.crt \
		-config https-proxy/key-config

https-proxy/tls.der.pub: https-proxy/tls.pem.crt
	openssl x509 -pubkey -noout -in https-proxy/tls.pem.crt -inform PEM -outform DER > https-proxy/tls.der.pub

https-proxy/tls.der.pub.mod: https-proxy/tls.der.pub
	openssl rsa -pubin -in https-proxy/tls.der.pub -modulus -noout | sed -e 's/^Modulus=//' | xxd -r -p > https-proxy/tls.der.pub.mod

https-proxy/nas.key:
	openssl genrsa -out https-proxy/nas.key 1024

https-proxy/nas.csr: https-proxy/nas.key
	openssl req -new -newkey rsa:1024 -key https-proxy/nas.key -out https-proxy/nas.csr -config https-proxy/nas-csr-config

https-proxy/nas.crt: https-proxy/nas.csr
	openssl x509 -req -in https-proxy/nas.csr -CA https-proxy/tls.pem.crt -CAkey https-proxy/tls.pem.key \
		-CAcreateserial -out https-proxy/nas.crt -days 825 -sha256 -extfile https-proxy/nas-crt-config

https-proxy/nas.chain.crt: https-proxy/nas.crt https-proxy/tls.pem.crt
	cat https-proxy/nas.crt https-proxy/tls.pem.crt > https-proxy/nas.chain.crt

rom/addr-domain: searchb-rs/target/release/searchb-rs
	searchb-rs/target/release/searchb-rs rom/orig-rom/domain $(INPUT_ROM_PATH) > rom/addr-domain

rom/addr-cert: searchb-rs/target/release/searchb-rs
	searchb-rs/target/release/searchb-rs rom/orig-rom/tls.der.pub.mod $(INPUT_ROM_PATH) > rom/addr-cert

rom/new-domain:
	echo -n $(DOMAIN) > rom/new-domain

rom/output.nds: rom/addr-domain rom/addr-cert rom/new-domain https-proxy/tls.der.pub.mod
	# copy rom
	cp $(INPUT_ROM_PATH) rom/output.nds
	# patch domain
	for offset in $$(cat rom/addr-domain); do dd if=rom/new-domain of=rom/output.nds obs=1 seek=$$offset conv=notrunc; done
	# patch cert
	for offset in $$(cat rom/addr-cert); do dd if=https-proxy/tls.der.pub.mod of=rom/output.nds obs=1 seek=$$offset conv=notrunc; done

.PHONY: docker-images
docker-images:
	docker compose build

.PHONY: run
run: docker-images https-proxy/nas.chain.crt https-proxy/nas.key
	docker compose up

.PHONY: clean
clean:
	rm -rf \
		rom/output.nds \
		searchb-rs/target \
		target \
		https-proxy/tls.pem.crt \
		https-proxy/tls.pem.key \
        https-proxy/tls.pem.srl \
		https-proxy/tls.der.pub \
		https-proxy/tls.der.pub.mod \
		https-proxy/nas.chain.crt \
        https-proxy/nas.crt \
        https-proxy/nas.csr \
        https-proxy/nas.key \
		rom/addr-domain \
		rom/addr-cert \
		rom/new-domain
	docker compose down
	docker image rm -f \
		pelipper-post-office \
		pelipper-post-office-https-proxy
