# ModSecurity Wasm Filter For Istio/Envoy Mesh

This is the source code of the [modsecurity-wasm-filter](https://github.com/intel/modsecurity-wasm-filter) for Istio/Envoy Mesh Http Filter.

We offer a Envoy WASM Plugin integrated with ModSecurity to implement the WAF functionality in the http filter chain. We containerd the WASM binary so users can easily deploy the filter in their istio/envoy Mesh.



### 1. Build and upload wasm plugin:

First, clone the repository and open into `wasmplugin` folder :

 ```
 git clone https://github.com/intel/modsecurity-wasm-filter.git 
 cd modsecurity-wasm-filter/wasmplugin
 ```

Run `docker build` to build modsecurity wasm plugin. This will generate a docker image containing a single wasm binary.

`docker build -t ${HUB}/${IMAGE_NAME}:${TAG} -f Dockerfile .`

Run `docker push` to push the binary to remote repository:

`docker push ${HUB}/${IMAGE_NAME}:${TAG}`



### 2. Intall Istio and httpbin example

make sure `istioctl` verison > 1.13

```
istioctl install --set meshConfig.defaultConfig.proxyMetadata.WASM_INSECURE_REGISTRIES=* -y
kubectl label namespace default istio-injection=enabled
kubectl apply -f https://raw.githubusercontent.com/istio/istio/release-1.14/samples/httpbin/httpbin.yaml
kubectl apply -f https://raw.githubusercontent.com/istio/istio/release-1.14/samples/httpbin/httpbin-gateway.yaml
```


### 3.  Build and deploy ruleserver controller  

Build ruleserver docker image:

```
cd modsecurity-wasm-filter/ruleserver
make docker-build IMG=ruleserver:crd
```

Deploy controller on kubernetes:

```
make deploy IMG=ruleserver:crd
```

Install CRD on kubernetes:

```
make install 
kubectl apply -f config/samples/
```


### 4. Test wasm filter

In another terminal, forward port 80 of istio ingressgateway to port 8080 of local machine

`kubectl port-forward -n istio-system svc/istio-ingressgateway 8080:80`

Send http request to see if the service is working as expected:

`curl -X POST -i http://localhost:8080/post?param1=test` will return HTTP 200 response

`curl -X POST -i http://localhost:8080/post?param1=attack` will return HTTP 400 response







