# Image URL to use all building/pushing image targets
REGISTRY ?= ghcr.io/hyperspike
IMG_CONTROLLER ?= $(REGISTRY)/valkey-operator:$(VERSION)
IMG_SIDECAR ?= $(REGISTRY)/valkey-sidecar:$(VERSION)
IMG_VALKEY ?= $(REGISTRY)/valkey:$(VALKEY_VERSION)
# ENVTEST_K8S_VERSION refers to the version of kubebuilder assets to be downloaded by envtest binary.

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

GO := $(shell which go)
MINIKUBE := $(shell which minikube)
KUBECTL := $(shell which kubectl)
VERSION ?= $(shell  if [ ! -z $$(git tag --points-at HEAD) ] ; then git tag --points-at HEAD|cat ; else  git rev-parse --short HEAD|cat; fi )
DATE ?= $(shell date -u  +'%Y%m%d')
SHA ?= $(shell git rev-parse --short HEAD)
PKG ?= hyperspike.io/valkey-operator
GOOS ?= linux
GOARCH ?= amd64

# CONTAINER_TOOL defines the container tool to be used for building images.
# Be aware that the target commands are only tested with Docker which is
# scaffolded by default. However, you might want to replace it to use other
# tools. (i.e. podman)
CONTAINER_TOOL ?= docker

# Setting SHELL to bash allows bash commands to be executed by recipes.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

K8S_VERSION ?= 1.34.1
ENVTEST_K8S_VERSION = $(K8S_VERSION)
CILIUM_VERSION ?= 1.18.1
VALKEY_VERSION ?= 8.1.3

V ?= 0
ifeq ($(V), 1)
	Q =
	VV = -v
else
	Q = @
	VV =
endif

.PHONY: all
all: build

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk command is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: manifests
manifests: controller-gen ## Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects.
	$Q$(CONTROLLER_GEN) rbac:roleName=manager-role crd webhook paths="./..." output:crd:artifacts:config=config/crd/bases

.PHONY: generate
generate: controller-gen ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	$Q$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."

.PHONY: fmt
fmt: ## Run go fmt against code.
	$Q$(GO) fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	$Q$(GO) vet $(VV) ./...

.PHONY: test
test: manifests generate fmt vet envtest ## Run tests.
	KUBEBUILDER_ASSETS="$(shell $(ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(LOCALBIN) -p path)" go test $$(go list ./... | grep -v /e2e) -coverprofile cover.out

# Utilize Kind or modify the e2e tests to load the image locally, enabling compatibility with other vendors.
.PHONY: test-e2e  # Run the e2e tests against a Kind k8s instance that is spun up.
test-e2e:
	go test ./test/e2e/ -v -ginkgo.v

.PHONY: lint
lint: golangci-lint ## Run golangci-lint linter
	$Q$(GOLANGCI_LINT) run

.PHONY: lint-fix
lint-fix: golangci-lint ## Run golangci-lint linter and perform fixes
	$Q$(GOLANGCI_LINT) run --fix

.PHONY: gosec
gosec: gosec-bin ## Run gosec scanner
	$Q$(GOSEC) ./...

##@ Build

manager: manifests generate fmt vet ## Build manager binary.
	$QCGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) $(GO) build $(VV) \
		-trimpath \
		-gcflags all="-N -l -trimpath=/src -trimpath=$(PWD)" \
		-asmflags all="-trimpath=/src -trimpath=$(PWD)" \
		-ldflags "-s -w -X main.BuildDate=$(DATE) -X main.Version=$(VERSION) -X main.Commit=$(SHA) \
			-X $(PKG)/cfg.DefaultSidecarImage=$(IMG_SIDECAR) -X $(PKG)/cfg.DefaultValkeyImage=$(IMG_VALKEY)" \
		-installsuffix cgo \
		-o $@ ./cmd/manager/

sidecar: manifests generate fmt vet ## Build sidecar binary.
	$QCGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) $(GO) build $(VV) \
		-trimpath \
		-gcflags all="-N -l -trimpath=/src -trimpath=$(PWD)" \
		-asmflags all="-trimpath=/src -trimpath=$(PWD)" \
		-ldflags "-s -w -X main.BuildDate=$(DATE) -X main.Version=$(VERSION) -X main.Commit=$(SHA) \
			-X $(PKG)/cfg.DefaultSidecarImage=$(IMG_SIDECAR) -X $(PKG)/cfg.DefaultValkeyImage=$(IMG_VALKEY)" \
		-installsuffix cgo \
		-o $@ ./cmd/sidecar/

build: manager sidecar ## Build manager and sidecar binaries.

.PHONY: run
run: manifests generate fmt vet ## Run a controller from your host.
	go run ./cmd/manager/main.go

# If you wish to build the manager image targeting other platforms you can use the --platform flag.
# (i.e. docker build --platform linux/arm64). However, you must enable docker buildKit for it.
# More info: https://docs.docker.com/develop/develop-images/build_enhancements/
.PHONY: docker-build docker-build-manager docker-build-sidecar docker-build-valkey
docker-build-manager: manager ## Build docker image with the manager.
	$(CONTAINER_TOOL) build -t ${IMG_CONTROLLER} -f Dockerfile.controller .

docker-build-sidecar: sidecar ## Build docker image with the sidecar binary.
	$(CONTAINER_TOOL) build -t ${IMG_SIDECAR} -f Dockerfile.sidecar .

docker-build-valkey: ## Build docker image with the valkey binary.
	$(CONTAINER_TOOL) build -t ${IMG_VALKEY} --build-arg VALKEY_VERSION=$(VALKEY_VERSION) -f Dockerfile.valkey .

docker-build: docker-build-manager docker-build-sidecar docker-build-valkey ## Build docker image with the manager, sidecar and valkey binaries.

.PHONY: docker-push
docker-push: ## Push docker image with the manager.
	$(CONTAINER_TOOL) push ${IMG_CONTROLLER}
	$(CONTAINER_TOOL) push ${IMG_SIDECAR}
	$(CONTAINER_TOOL) push ${IMG_VALKEY}

# PLATFORMS defines the target platforms for the manager image be built to provide support to multiple
# architectures. (i.e. make docker-buildx IMG=myregistry/mypoperator:0.0.1). To use this option you need to:
# - be able to use docker buildx. More info: https://docs.docker.com/build/buildx/
# - have enabled BuildKit. More info: https://docs.docker.com/develop/develop-images/build_enhancements/
# - be able to push the image to your registry (i.e. if you do not set a valid value via IMG=<myregistry/image:<tag>> then the export will fail)
# To adequately provide solutions that are compatible with multiple platforms, you should consider using this option.
PLATFORMS ?= linux/arm64,linux/amd64,linux/s390x,linux/ppc64le
.PHONY: docker-buildx
docker-buildx: ## Build and push docker image for the manager for cross-platform support
	# copy existing Dockerfile and insert --platform=${BUILDPLATFORM} into Dockerfile.cross, and preserve the original Dockerfile
	sed -e '1 s/\(^FROM\)/FROM --platform=\$$\{BUILDPLATFORM\}/; t' -e ' 1,// s//FROM --platform=\$$\{BUILDPLATFORM\}/' Dockerfile.controller > Dockerfile.controller.cross
	- $(CONTAINER_TOOL) buildx create --name valkey-operator-builder
	$(CONTAINER_TOOL) buildx use valkey-operator-builder
	- $(CONTAINER_TOOL) buildx build --push --platform=$(PLATFORMS) --tag ${IMG_CONTROLLER} -f Dockerfile.controller.cross .
	- $(CONTAINER_TOOL) buildx rm valkey-operator-builder
	rm Dockerfile.controller.cross

.PHONY: build-installer
build-installer: manifests generate kustomize ## Generate a consolidated YAML with CRDs and deployment.
	$Qmkdir -p dist
	$Qcd config/manager && $(KUSTOMIZE) edit set image controller=${IMG_CONTROLLER}
	$Q$(KUSTOMIZE) build config/default > dist/install.yaml

##@ Deployment

ifndef ignore-not-found
  ignore-not-found = false
endif

.PHONY: install
install: manifests kustomize ## Install CRDs into the K8s cluster specified in ~/.kube/config.
	$(KUSTOMIZE) build config/crd | $(KUBECTL) apply -f -

.PHONY: uninstall
uninstall: manifests kustomize ## Uninstall CRDs from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	$(KUSTOMIZE) build config/crd | $(KUBECTL) delete --ignore-not-found=$(ignore-not-found) -f -

.PHONY: deploy
deploy: manifests kustomize ## Deploy controller to the K8s cluster specified in ~/.kube/config.
	cd config/manager && $(KUSTOMIZE) edit set image controller=${IMG_CONTROLLER}
	$(KUSTOMIZE) build config/default | $(KUBECTL) apply -f -

.PHONY: undeploy
undeploy: kustomize ## Undeploy controller from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	$(KUSTOMIZE) build config/default | $(KUBECTL) delete --ignore-not-found=$(ignore-not-found) -f -

##@ Quickstart

.PHONY: minikube
minikube: ## Spool up a local minikube cluster for development
	$QK8S_VERSION=$(K8S_VERSION) \
		CILIUM_VERSION=$(CILIUM_VERSION) \
		CERTMANAGER_VERSION=$(CERTMANAGER_VERSION) \
		TLS=$(TLS) \
		PROMETHEUS=$(PROMETHEUS) \
		hack/minikube.sh

.PHONY: quickstart install-operator install-cr
quickstart: minikube install-operator install-cr ## Install the operator into the minikube cluster and deploy the sample CR use the TLS and PROMETHEUS variables to enable those features

install-operator: ## Install the operator into the minikube cluster
	$QLATEST=$(shell curl -s https://api.github.com/repos/hyperspike/valkey-operator/releases/latest | jq -Mr .tag_name) \
		&& curl -sL https://github.com/hyperspike/valkey-operator/releases/download/$$LATEST/install.yaml | kubectl apply -f -
install-cr: ## Install the sample CR into the minikube cluster
	$Q(if [ ! -z $$TLS ] ; then TLS_VALUE=true ; else TLS_VALUE=false ; fi ; if [ ! -z $$PROMETHEUS ] ; then PROMETHEUS_VALUE=true ; else PROMETHEUS_VALUE=false ; fi ;  sed -e "s/@TLS@/$$TLS_VALUE/" -e "s/@PROMETHEUS@/$$PROMETHEUS_VALUE/" valkey.yml.tpl | $(KUBECTL) apply -f - )

minikube-delete: ## Delete the minikube cluster
	$Qminikube delete -p north

##@ Dependencies

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

## Tool Binaries
KUBECTL ?= $(shell which kubectl)
KUSTOMIZE ?= $(LOCALBIN)/kustomize-$(KUSTOMIZE_VERSION)
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen-$(CONTROLLER_TOOLS_VERSION)
ENVTEST ?= $(LOCALBIN)/setup-envtest-$(ENVTEST_VERSION)
GOLANGCI_LINT ?= $(LOCALBIN)/golangci-lint-$(GOLANGCI_LINT_VERSION)
HELMIFY ?= $(LOCALBIN)/helmify-$(HELMIFY_VERSION)
HELM ?= $(LOCALBIN)/helm-$(HELM_VERSION)
GOSEC ?= $(LOCALBIN)/gosec-$(GOSEC_VERSION)

## Tool Versions
KUSTOMIZE_VERSION ?= v5.4.1
CONTROLLER_TOOLS_VERSION ?= v0.17.3
ENVTEST_VERSION ?= release-0.18
GOLANGCI_LINT_VERSION ?= v1.61.0
HELMIFY_VERSION ?= v0.4.14
HELM_VERSION ?= v3.15.4
GOSEC_VERSION ?= v2.22.1

helm-gen: manifests kustomize helmify ## Generate Helm chart from Kustomize manifests
	$Qcd config/manager && $(KUSTOMIZE) edit set image controller=${IMG_CONTROLLER}
	$Q$(KUSTOMIZE) build config/default | $(HELMIFY) -crd-dir valkey-operator
	$Qsed s@\\\(app.kubernetes.io/name\\\)@\'\\\1\'@ -i valkey-operator/templates/deployment.yaml
	$Qsed s@\\\(app.kubernetes.io/instance\\\)@\'\\\1\'@ -i valkey-operator/templates/deployment.yaml

helm-package: helm-gen helm ## Package Helm chart
	$Q$(HELM) package valkey-operator --app-version $(VERSION) --version $(VERSION)-chart

helm-publish: helm-package ## Publish Helm chart
	$Q$(HELM) push valkey-operator-$(VERSION)-chart.tgz oci://ghcr.io/hyperspike

.PHONY: tunnel registry-proxy prometheus-proxy
tunnel: ## turn on minikube's tunnel to test ingress and get UI access
	$Q$(MINIKUBE) tunnel -p north

registry-proxy: ## turn on a port to push locally built containers into the cluster
	$Q$(KUBECTL) port-forward --namespace kube-system service/registry 5000:80
prometheus-proxy: ## turn on a port to validate prometheus metrics
	$Q$(KUBECTL) port-forward --namespace default svc/prometheus 9090:9090

.PHONY: kustomize
kustomize: $(KUSTOMIZE) ## Download kustomize locally if necessary.
$(KUSTOMIZE): $(LOCALBIN)
	$(call go-install-tool,$(KUSTOMIZE),sigs.k8s.io/kustomize/kustomize/v5,$(KUSTOMIZE_VERSION))

.PHONY: controller-gen
controller-gen: $(CONTROLLER_GEN) ## Download controller-gen locally if necessary.
$(CONTROLLER_GEN): $(LOCALBIN)
	$(call go-install-tool,$(CONTROLLER_GEN),sigs.k8s.io/controller-tools/cmd/controller-gen,$(CONTROLLER_TOOLS_VERSION))

.PHONY: envtest
envtest: $(ENVTEST) ## Download setup-envtest locally if necessary.
$(ENVTEST): $(LOCALBIN)
	$(call go-install-tool,$(ENVTEST),sigs.k8s.io/controller-runtime/tools/setup-envtest,$(ENVTEST_VERSION))

.PHONY: golangci-lint
golangci-lint: $(GOLANGCI_LINT) ## Download golangci-lint locally if necessary.
$(GOLANGCI_LINT): $(LOCALBIN)
	$(call go-install-tool,$(GOLANGCI_LINT),github.com/golangci/golangci-lint/cmd/golangci-lint,$(GOLANGCI_LINT_VERSION))

.PHONY: helmify
helmify: $(HELMIFY) ## Download helmify locally if necessary.
$(HELMIFY): $(LOCALBIN)
	$(call go-install-tool,$(HELMIFY),github.com/arttor/helmify/cmd/helmify,$(HELMIFY_VERSION))

.PHONY: helm
helm: $(HELM) ## Download helm locally if necessary.
$(HELM): $(LOCALBIN)
	$(call go-install-tool,$(HELM),helm.sh/helm/v3/cmd/helm,$(HELM_VERSION))

.PHONY: gosec-bin
gosec-bin: $(GOSEC) ## Download gosec locally if necessary.
$(GOSEC): $(LOCALBIN)
	$(call go-install-tool,$(GOSEC),github.com/securego/gosec/v2/cmd/gosec,${GOSEC_VERSION})

# go-install-tool will 'go install' any package with custom target and name of binary, if it doesn't exist
# $1 - target path with name of binary (ideally with version)
# $2 - package url which can be installed
# $3 - specific version of package
define go-install-tool
@[ -f $(1) ] || { \
set -e; \
package=$(2)@$(3) ;\
echo "Downloading $${package}" ;\
GOOS=linux GOARCH=amd64 GOBIN=$(LOCALBIN) go install $${package} ;\
mv "$$(echo "$(1)" | sed "s/-$(3)$$//")" $(1) ;\
}
endef

# CHANNELS define the bundle channels used in the bundle.
# Add a new line here if you would like to change its default config. (E.g CHANNELS = "candidate,fast,stable")
# To re-generate a bundle for other specific channels without changing the standard setup, you can:
# - use the CHANNELS as arg of the bundle target (e.g make bundle CHANNELS=candidate,fast,stable)
# - use environment variables to overwrite this value (e.g export CHANNELS="candidate,fast,stable")
ifneq ($(origin CHANNELS), undefined)
BUNDLE_CHANNELS := --channels=$(CHANNELS)
endif

# DEFAULT_CHANNEL defines the default channel used in the bundle.
# Add a new line here if you would like to change its default config. (E.g DEFAULT_CHANNEL = "stable")
# To re-generate a bundle for any other default channel without changing the default setup, you can:
# - use the DEFAULT_CHANNEL as arg of the bundle target (e.g make bundle DEFAULT_CHANNEL=stable)
# - use environment variables to overwrite this value (e.g export DEFAULT_CHANNEL="stable")
ifneq ($(origin DEFAULT_CHANNEL), undefined)
BUNDLE_DEFAULT_CHANNEL := --default-channel=$(DEFAULT_CHANNEL)
endif
BUNDLE_METADATA_OPTS ?= $(BUNDLE_CHANNELS) $(BUNDLE_DEFAULT_CHANNEL)

# IMAGE_TAG_BASE defines the docker.io namespace and part of the image name for remote images.
# This variable is used to construct full image tags for bundle and catalog images.
#
# For example, running 'make bundle-build bundle-push catalog-build catalog-push' will build and push both
# my.domain/test-bundle:$VERSION and my.domain/test-catalog:$VERSION.
IMAGE_TAG_BASE ?= my.domain/test

# BUNDLE_IMG defines the image:tag used for the bundle.
# You can use it as an arg. (E.g make bundle-build BUNDLE_IMG=<some-registry>/<project-name-bundle>:<tag>)
BUNDLE_IMG ?= $(IMAGE_TAG_BASE)-bundle:v$(VERSION)

# BUNDLE_GEN_FLAGS are the flags passed to the operator-sdk generate bundle command
BUNDLE_GEN_FLAGS ?= -q --overwrite --version $(VERSION) $(BUNDLE_METADATA_OPTS)

# USE_IMAGE_DIGESTS defines if images are resolved via tags or digests
# You can enable this value if you would like to use SHA Based Digests
# To enable set flag to true
USE_IMAGE_DIGESTS ?= false
ifeq ($(USE_IMAGE_DIGESTS), true)
	BUNDLE_GEN_FLAGS += --use-image-digests
endif

# Set the Operator SDK version to use. By default, what is installed on the system is used.
# This is useful for CI or a project to utilize a specific version of the operator-sdk toolkit.
OPERATOR_SDK_VERSION ?= v1.39.1

.PHONY: operator-sdk
OPERATOR_SDK ?= $(LOCALBIN)/operator-sdk
operator-sdk: ## Download operator-sdk locally if necessary.
ifeq (,$(wildcard $(OPERATOR_SDK)))
ifeq (, $(shell which operator-sdk 2>/dev/null))
	@{ \
	set -e ;\
	mkdir -p $(dir $(OPERATOR_SDK)) ;\
	OS=$(shell go env GOOS) && ARCH=$(shell go env GOARCH) && \
	curl -sSLo $(OPERATOR_SDK) https://github.com/operator-framework/operator-sdk/releases/download/$(OPERATOR_SDK_VERSION)/operator-sdk_$${OS}_$${ARCH} ;\
	chmod +x $(OPERATOR_SDK) ;\
	}
else
OPERATOR_SDK = $(shell which operator-sdk)
endif
endif

.PHONY: bundle
bundle: manifests kustomize operator-sdk ## Generate bundle manifests and metadata, then validate generated files.
	$(OPERATOR_SDK) generate kustomize manifests -q
	cd config/manager && $(KUSTOMIZE) edit set image controller=$(IMG_CONTROLLER)
	$(KUSTOMIZE) build config/manifests | $(OPERATOR_SDK) generate bundle $(BUNDLE_GEN_FLAGS)
	$(OPERATOR_SDK) bundle validate ./bundle

.PHONY: bundle-build
bundle-build: ## Build the bundle image.
	docker build -f bundle.Dockerfile -t $(BUNDLE_IMG) .

.PHONY: bundle-push
bundle-push: ## Push the bundle image.
	$(MAKE) docker-push IMG=$(BUNDLE_IMG)

.PHONY: opm
OPM = $(LOCALBIN)/opm
opm: ## Download opm locally if necessary.
ifeq (,$(wildcard $(OPM)))
ifeq (,$(shell which opm 2>/dev/null))
	@{ \
	set -e ;\
	mkdir -p $(dir $(OPM)) ;\
	OS=$(shell go env GOOS) && ARCH=$(shell go env GOARCH) && \
	curl -sSLo $(OPM) https://github.com/operator-framework/operator-registry/releases/download/v1.23.0/$${OS}-$${ARCH}-opm ;\
	chmod +x $(OPM) ;\
	}
else
OPM = $(shell which opm)
endif
endif

# A comma-separated list of bundle images (e.g. make catalog-build BUNDLE_IMGS=example.com/operator-bundle:v0.1.0,example.com/operator-bundle:v0.2.0).
# These images MUST exist in a registry and be pull-able.
BUNDLE_IMGS ?= $(BUNDLE_IMG)

# The image tag given to the resulting catalog image (e.g. make catalog-build CATALOG_IMG=example.com/operator-catalog:v0.2.0).
CATALOG_IMG ?= $(IMAGE_TAG_BASE)-catalog:v$(VERSION)

# Set CATALOG_BASE_IMG to an existing catalog image tag to add $BUNDLE_IMGS to that image.
ifneq ($(origin CATALOG_BASE_IMG), undefined)
FROM_INDEX_OPT := --from-index $(CATALOG_BASE_IMG)
endif

# Build a catalog image by adding bundle images to an empty catalog using the operator package manager tool, 'opm'.
# This recipe invokes 'opm' in 'semver' bundle add mode. For more information on add modes, see:
# https://github.com/operator-framework/community-operators/blob/7f1438c/docs/packaging-operator.md#updating-your-existing-operator
.PHONY: catalog-build
catalog-build: opm ## Build a catalog image.
	$(OPM) index add --container-tool docker --mode semver --tag $(CATALOG_IMG) --bundles $(BUNDLE_IMGS) $(FROM_INDEX_OPT)

# Push the catalog image.
.PHONY: catalog-push
catalog-push: ## Push a catalog image.
	$(MAKE) docker-push IMG=$(CATALOG_IMG)
