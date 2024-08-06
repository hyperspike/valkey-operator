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
make minikube
kubectl apply -f https://raw.githubusercontent.com/hyperspike/valkey-operator/main/dist/install.yaml
```

Create a ValkeyCluster
```sh
kubectl apply -f https://raw.githubusercontent.com/hyperspike/valkey-operator/main/valkey.yaml
```

### To Uninstall

```sh
minikube delete -p north
```


## Project Distribution

Following are the steps to build the installer and distribute this project to users.

1. Build the installer for the image built and published in the registry:

```sh
make build-installer IMG=<some-registry>/valkey-operator:tag
```

NOTE: The makefile target mentioned above generates an 'install.yaml'
file in the dist directory. This file contains all the resources built
with Kustomize, which are necessary to install this project without
its dependencies.

2. Using the installer

Users can just run kubectl apply -f <URL for YAML BUNDLE> to install the project, i.e.:

```sh
kubectl apply -f https://raw.githubusercontent.com/hyperspike/valkey-operator/main/dist/install.yaml
```

## Contributing
// TODO(user): Add detailed information on how you would like others to contribute to this project

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

