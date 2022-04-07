# ModSecurity Wasm Filter For Istio/Envoy Mesh

This is the source code of the [modsecurity-wasm-filter](https://github.com/intel/modsecurity-wasm-filter) for Istio/Envoy Mesh Http Filter.

We offer a Envoy WASM Plugin integrated with ModSecurity to implement the WAF functionality in the http filter chain. We containerd the WASM binary so users can easily deploy the filter in their istio/envoy mesh.

The plugin is the basic version and the modsecurity rule inside the plugin can be updated by the istio CR `WasmPlugin`. And we support dynamic update of the wasm binary and modsecurity rules based on istio > 1.13. The rule server for OWASP rules and customer rules will be delivered in the future.



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



### 2. Deploy wasm plugin into istio-ingressgateway http filter chain

#### Get binding port for http2

```
kubectl get svc istio-ingressgateway -n istio-system

NAME                   TYPE       CLUSTER-IP    EXTERNAL-IP   PORT(S)                                      AGE
istio-ingressgateway   NodePort   $CLUSTER-IP   <none>        15021:31164/TCP,80:30829/TCP,443:30501/TCP   28d
```

The output here shows that the `istio-ingressgateway` service is forwarding requests from port `80` to port `30829`

Update `/rule-service/rule-service.yaml` to make sure the `nodeport` value of the service be the same with the `istio-ingressgateway` forwarding `nodeport` value.

#### Enable automatic proxy sidecar injection:

`kubectl label namespaces default istio-injection=enabled`

#### Create config map from custom modsecurity.conf

`kubectl create cm rule-configmap --from-file=index.html= rule-example/modsecurity.conf`


#### Create rule-service 

`kubectl apply -f rule-service/rule-service.yaml` 

#### Enable wasmplugin

`kubectl apply -f istio/mod-wasm-deploy.yaml`



### 3. Test modsecurity wasm plugin with istio-ingressgateway

#### Set up ingress ports:

```
export INGRESS_PORT=$(kubectl -n istio-system get service istio-ingressgateway -o jsonpath='{.spec.ports[?(@.name=="http2")].nodePort}')

export SECURE_INGRESS_PORT=$(kubectl -n istio-system get service istio-ingressgateway -o jsonpath='{.spec.ports[?(@.name=="https")].nodePort}')

export TCP_INGRESS_PORT=$(kubectl -n istio-system get service istio-ingressgateway -o jsonpath='{.spec.ports[?(@.name=="tcp")].nodePort}')

export INGRESS_HOST=$(kubectl get po -l istio=ingressgateway -n istio-system -o jsonpath='{.items[0].status.hostIP}')
```

#### Create an ingress gateway for the service: 

```
kubectl apply -f - <<EOF
apiVersion: networking.istio.io/v1alpha3
kind: Gateway
metadata:
  name: mygateway
spec:
  selector:
    istio: ingressgateway # use Istio default gateway implementation
  servers:
  - port:
      number: 80
      name: http
      protocol: HTTP
    hosts:
    - "nginx.example.com"
EOF
```

#### Create a virtual service for the ingress gateway:

```
kubectl apply -f - <<EOF
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: nginx
spec:
  hosts:
  - "nginx.example.com"
  gateways:
  - mygateway
  http:
  - match:
    - uri:
        prefix: /
    route:
    - destination:
        port:
          number: 80
        host: testapp
EOF
```

To confirm the ingress gateway is working properly, using the following command:

This should return HTTP 200 OK:

`curl -v -HHost:nginx.example.com http://$INGRESS_HOST:$INGRESS_PORT?param1=test`

This should return HTTP 404 Not Found:

`curl -v -HHost:nginx.example.com http://$INGRESS_HOST:$INGRESS_PORT?param1=attack`
