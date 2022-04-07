# ModSecurity Wasm Filter For Istio/Envoy Mesh

This is the source code of the [modsecurity-wasm-filter](https://github.com/intel/modsecurity-wasm-filter) for Istio/Envoy Mesh Http Filter.

We offer a Envoy WASM Plugin integrated with ModSecurity to implement the WAF functionality in the http filter chain. We containerd the WASM binary so users can easily deploy the filter in their istio/envoy mesh.

The plugin is the basic version and the modsecurity rule inside the plugin can be updated by the istio CR `WasmPlugin`. And we support dynamic update of the wasm binary and modsecurity rules based on istio > 1.13. The rule server for OWASP rules and customer rules will be delivered in the future.
