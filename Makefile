INPUT_ROM_PATH := "rom/input.nds"
DOMAIN := "wc.skytemple.org"

default: rom/output.nds docker-images

searchb-rs/target/release/searchb-rs:
	cd searchb-rs; cargo build --release

rom/new-domain:
	echo -n $(DOMAIN) > rom/new-domain

rom/new-nas-route: rom/new-domain
	echo -n "http://nas.$(DOMAIN)/ac" > rom/new-nas-route
	truncate -s +1 rom/new-nas-route

rom/output.nds rom/addr-nas-route rom/addr-domain: searchb-rs/target/release/searchb-rs rom/new-domain rom/new-nas-route
	# copy rom
	cp $(INPUT_ROM_PATH) rom/output.nds
	# patch nas routes
	searchb-rs/target/release/searchb-rs rom/orig-rom/nas-route rom/output.nds > rom/addr-nas-route
	for offset in $$(cat rom/addr-nas-route); do dd if=rom/new-nas-route of=rom/output.nds obs=1 seek=$$offset conv=notrunc; done
	# patch domain
	searchb-rs/target/release/searchb-rs rom/orig-rom/domain rom/output.nds > rom/addr-domain
	for offset in $$(cat rom/addr-domain); do dd if=rom/new-domain of=rom/output.nds obs=1 seek=$$offset conv=notrunc; done

.PHONY: docker-images
docker-images:
	docker compose build

.PHONY: run
run: docker-images
	docker compose up

.PHONY: clean
clean:
	rm -rf \
		rom/output.nds \
		searchb-rs/target \
		target \
		rom/addr-domain \
		rom/new-domain
	docker compose down
	docker image rm -f \
		pelipper-post-office
