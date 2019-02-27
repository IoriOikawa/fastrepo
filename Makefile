# Copyright (c) {Iori, Cocoa} Oikawa @ Meowtain
# Distributed under the terms of the Modified BSD License.

include .env
.DEFAULT_GOAL=build

volumes:
	@docker volume inspect $(MAGIC_MIRROR_HOST) >/dev/null 2>&1 || docker volume create --name $(MAGIC_MIRROR_HOST)


overlay/certs/fullchain.pem:
	@if [ ! -f "overlay/certs/fullchain.pem" ]; then echo "Need an SSL certificate in overlay/certs/fullchain.pem"; exit 1; fi

overlay/certs/privkey.pem:
	@if [ ! -f "overlay/certs/privkey.pem" ]; then echo "Need an SSL private key in overlay/certs/privkey.pem"; exit 1; fi

overlay/config.json:
	@if [ ! -f "overlay/config.json" ]; then echo -e "Need a config file in overlay/config.json\nYou may refer to config.json.exmaple"; exit 1; fi

check-files: overlay/certs/fullchain.pem overlay/certs/privkey.pem overlay/config.json
	@echo "OK to proceed"

pull:
	docker pull ubuntu:18.04

build: check-files volumes pull
	docker-compose build

.PHONY: check-files volumes pull build
