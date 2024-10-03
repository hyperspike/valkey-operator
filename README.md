# valkey-operator

Provision [valkey](https://valkey.io) (redis) clusters

## Description

This operator creates valkey clusters and makes them available to other services on the k8s cluster

See the following link for more information on avialable Custom Resource Options: [https://doc.crds.dev/github.com/hyperspike/valkey-operator](https://doc.crds.dev/github.com/hyperspike/valkey-operator)

## Getting Started

### Prerequisites
- go version v1.22.0+
- docker version 17.03+.
- kubectl version v1.11.3+.
- Access to a Kubernetes v1.11.3+ cluster.

### Quick Start

Deploy kubernetes locally using minikube, and install the controller:
```sh
make quickstart
```

and optionally, turn on TLS and Prometheus:
```sh
make quickstart TLS=1 PROMETHEUS=1
```


### To Uninstall

```sh
minikube delete -p north
```


## Project Distribution

### Vanilla Kubernetes Manifests

To install the valkey-operator, all you need to do is run the following command:

```sh
LATEST=$(curl -s https://api.github.com/repos/hyperspike/valkey-operator/releases/latest | jq -cr .tag_name)
curl -sL https://github.com/hyperspike/valkey-operator/releases/download/$LATEST/install.yaml | kubectl create -f -
```

### Helm

```sh
LATEST=$(curl -s https://api.github.com/repos/hyperspike/valkey-operator/releases/latest | jq -cr .tag_name)
helm install valkey-operator --namespace valkey-operator-system --create-namespace oci://ghcr.io/hyperspike/valkey-operator --version ${LATEST}-chart
```

### Verifying the container image

```sh
LATEST=$(curl -s https://api.github.com/repos/hyperspike/valkey-operator/releases/latest | jq -cr .tag_name)
cosign verify ghcr.io/hyperspike/valkey-operator:$LATEST  --certificate-oidc-issuer https://token.actions.githubusercontent.com --certificate-identity https://github.com/hyperspike/valkey-operator/.github/workflows/image.yaml@refs/tags/$LATEST
```

## Contributing

**NOTE:** Run `make help` for more information on all potential `make` targets

More information can be found via the [Kubebuilder Documentation](https://book.kubebuilder.io/introduction.html)

Spool up a local cluster:
```sh
make minikube
```

Proxy to the registry on the local cluster:
```sh
make registry-proxy
```

And deploy the operator:
```sh
TAG=1; make docker-build IMG=localhost:5000/controller:$TAG; docker push localhost:5000/controller:$TAG ; make IMG=localhost:5000/controller:$TAG build-installer  ; kubectl apply -f dist/install.yaml
```

## License

Copyright 2024.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

