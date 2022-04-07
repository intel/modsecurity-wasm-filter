all: envoy-wasm-modsecurity-dynamic.wasm

PROXY_WASM_CPP_SDK=/sdk
CPP_API:=${PROXY_WASM_CPP_SDK}
CPP_CONTEXT_LIB = ${CPP_API}/proxy_wasm_intrinsics.cc
ABSL = /root/abseil-cpp
ABSL_CPP = ${ABSL}/absl/strings/str_cat.cc ${ABSL}/absl/strings/str_split.cc ${ABSL}/absl/strings/numbers.cc ${ABSL}/absl/strings/ascii.cc
MODSECURITY = /usr/local/modsecurity/
PCRE = /usr/local/pcre/
ISTIO_PROXY = /root/istio-proxy
JSON_UTIL = /root/istio-proxy/extensions/common/wasm

%.wasm %.wat: %.cc ${CPP_API}/proxy_wasm_intrinsics.h ${CPP_API}/proxy_wasm_enums.h ${CPP_API}/proxy_wasm_externs.h ${CPP_API}/proxy_wasm_api.h ${CPP_API}/proxy_wasm_intrinsics.js ${CPP_CONTEXT_LIB}
	em++ --no-entry -s EXPORTED_FUNCTIONS=['_malloc'] --std=c++17 -O3 -flto -DPROXY_WASM_PROTOBUF_LITE=1 -I${CPP_API} -I${PROXY_WASM_CPP_SDK} -L${MODSECURITY}/lib/ -lmodsecurity -L${PCRE} -lpcre -I${ISTIO_PROXY} -I${CPP_API}/google/protobuf -I/usr/local/include -I${ABSL} --js-library ${CPP_API}/proxy_wasm_intrinsics.js ${ABSL_CPP} $*.cc ${CPP_API}/proxy_wasm_intrinsics.pb.cc ${JSON_UTIL}/json_util.cc utils.cc ${CPP_CONTEXT_LIB} ${CPP_API}/libprotobuf.a -o $*.wasm -I${MODSECURITY}/include/
