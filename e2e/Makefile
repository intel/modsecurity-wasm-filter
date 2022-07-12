IMAGE_NAME=intel/modsecurity-wasm-filter-static
IMAGE_VERSION?=latest
EXTRACT_CONTAINER_NAME=modsecurity-wasm-filter-static-extract

build-wasm-plugin-static:
	sed -i 's/envoy-wasm-modsecurity-dynamic/envoy-wasm-modsecurity/' ../wasmplugin/Dockerfile
	sed -i 's/envoy-wasm-modsecurity-dynamic/envoy-wasm-modsecurity/' ../wasmplugin/Makefile
	docker build --platform linux/amd64 -t $(IMAGE_NAME):$(IMAGE_VERSION) -f ../wasmplugin/Dockerfile ../wasmplugin
	# Go back to old state
	cd ../wasmplugin; git checkout .

extract-wasm-plugin-static:
	@docker rm -f $(EXTRACT_CONTAINER_NAME) || true
	@docker create --rm --name $(EXTRACT_CONTAINER_NAME) $(IMAGE_NAME):$(IMAGE_VERSION) /plugin.wasm
	@mkdir ./build
	@docker cp $(EXTRACT_CONTAINER_NAME):/plugin.wasm ./build/modsecurity-filter.wasm
	@docker rm -f $(EXTRACT_CONTAINER_NAME)

