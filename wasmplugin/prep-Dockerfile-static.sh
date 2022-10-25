#!/bin/bash

cp Dockerfile Dockerfile-static
sed -i 's/envoy-wasm-modsecurity-dynamic/envoy-wasm-modsecurity/' ./Dockerfile-static
sed -i 's/\&\& make\s*$/\&\& make envoy-wasm-modsecurity.wasm/' ./Dockerfile-static