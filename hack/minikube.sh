#!/bin/sh


export CILIUM_CLI_MODE=classic
export SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )


bootcluster_linux() {
	name=$1
	clusterid=$2
	podcidr=$3
	servicecidr=$4

	helm repo add cilium https://helm.cilium.io/ || true
	helm repo update cilium
	helm pull cilium/cilium --untar

	echo "---
kind: ConfigMap
apiVersion: v1
metadata:
  name: blank-cni
  namespace: kube-system
data:
  description: This CM intentioanlly left blank to fake out minikube/kubeadm
" > blank.yaml
	minikube start --memory 4g --container-runtime=cri-o \
		--kubernetes-version=v${K8S_VERSION} \
		--extra-config kubeadm.pod-network-cidr=$podcidr \
		--service-cluster-ip-range $servicecidr \
		--extra-config kubeadm.skip-phases=addon/kube-proxy \
		--network north-south \
		--subnet 10.59.0.0/16 \
		--host-only-cidr 10.59.0.0/16 \
		--dns-domain cluster.$name --cni=blank.yaml --profile=$name

	echo "---
apiVersion: v1
kind: ConfigMap
metadata:
  name: bgp-config
  namespace: kube-system
data:
  config.yaml: |
    peers: []
    #- peer-address: 10.0.0.1
    #  peer-asn: 64512
    #  my-asn: 64512
    address-pools: []
    #- name: default
    #  protocol: bgp
    #  addresses:
    #  - 192.168.39.0/24
---
" > .cni-$name.yaml
	helm template cilium cilium --validate --version ${CILIUM_VERSION} --namespace kube-system \
		--set cluster.name=$name \
		--set cluster.id=$clusterid \
		--set externalIPs.enabled=true \
		--set ipam.operator.clusterPoolIPv4PodCIDRList=$podcidr  \
		--set ipv4NativeRoutingCIDR=10.0.0.0/8 \
		--set routingMode="native" \
		--set autoDirectNodeRoutes=true \
		--set operator.replicas=1 \
		--set socketLB.enabled=true \
		--set kubeProxyReplacement=true \
		--set k8sServiceHost=$(minikube ip -p $name) \
		--set hubble.relay.enabled=true \
		--set hubble.peerService.clusterDomain=cluster.$name \
		--set hubble.ui.enabled=true \
		--set hubble.metrics.enableOpenMetrics=true \
		--set hubble.metrics.enabled="{dns,drop,tcp,flow,port-distribution,icmp,httpV2:exemplars=true;labelsContext=source_ip\,source_namespace\,source_workload\,destination_ip\,destination_namespace\,destination_workload\,traffic_direction}" \
		--set ingressController.enabled=true \
		--set ingressController.loadbalancerMode=dedicated \
		--set ingressController.secretsNamespace.name=kube-system \
		--set ingressController.secretsNamespace.create=false \
		--set localRedirectPolicy=true \
		--set l2announcements.enabled=true \
		--set l2podAnnouncements.enabled=true \
		--set loadBalancer.l7.backend=envoy \
		--set-string extraConfig.enable-envoy-config=true \
		--set socketLB.hostNamespaceOnly=true \
		--set hostPort.enabled=true \
		--set externalIPs.enabled=true \
		--set bgpControlPlane.enabled=true \
		--set endpointRoutes.enabled=true \
		--set nodePort.enabled=true \
		--set k8sServicePort=8443 >> .cni-$name.yaml
		#--set authentication.enabled=true \
		#--set authentication.mutual.spire.enabled=true \
		#--set authentication.mutual.spire.install.enabled=true \
		#--set authentication.mutual.spire.serverAddress=spire-server.cilium-spire.svc.cluster.$name:8081 \
		#--set tunnel=disabled \
		#--set tunnelProtocol="" \
		#--set endpointStatus.enabled=true \
		#--set endpointStatus.status=policy \
		#--set clustermesh.useAPIServer=true \
		#--set clustermesh.config.enabled=true \
		#--set encryption.enabled=true \
		#--set encryption.type=wireguard \
		#--set encryption.nodeEncryption=true \
		#--set encryption.wireguard.userspaceFallback=true \
		#--set clustermesh.config.domain=$name.mesh.cilium.io \
		#--set clustermesh.apiserver.kvstoremesh.enabled=true \
		#--set clustermesh.apiserver.replicas=3 \
	minikube kubectl  -p $name --  apply -f .cni-$name.yaml
	minikube node add -p $name
	minikube node add -p $name
	# sleep 15 #@TODO build a watch loop
}

bootcluster_macos() {
	name=$1
	clusterid=$2
	podcidr=$3
	servicecidr=$4

	minikube start --memory 4g --container-runtime=cri-o \
		--kubernetes-version=v${K8S_VERSION} \
		--extra-config kubeadm.pod-network-cidr=$podcidr \
		--service-cluster-ip-range $servicecidr \
		--network north-south \
		--subnet 10.59.0.0/16 \
		--host-only-cidr 10.59.0.0/16 \
		--dns-domain cluster.$name --cni=cilium --profile=$name
}

addons() {
	kubectl delete pod -l k8s-app=kube-dns -n kube-system
	minikube addons enable registry -p north --images='Registry=docker.io/registry:2.8.3,KubeRegistryProxy=gcr.io/k8s-minikube/kube-registry-proxy:0.0.9'
	# use the addon, but through a tunnel
	#minikube addons enable ingress  -p north
	#kubectl get svc -n ingress-nginx ingress-nginx-controller  -o yaml > .ingress.yaml
	#sed -i'' -e 's/NodePort/LoadBalancer/' -e '/allocateNode/d' .ingress.yaml
	#kubectl apply -f .ingress.yaml
	#kubectl apply -f scripts/ingress.yaml
	#kubectl delete po -n ingress-nginx -l app.kubernetes.io/component=controller
	kubectl delete pod -l k8s-app=kube-dns -n kube-system
	kubectl get deployment -n kube-system coredns -o yaml > .coredns.yaml
	sed -i'' -e 's/\(replicas:\).*/\1\ 2/' .coredns.yaml
	kubectl apply -f .coredns.yaml
	#kubectl apply -f $SCRIPT_DIR/postgres-operator.yaml
	#kubectl apply -f $SCRIPT_DIR/minikube-pvc-hack.yaml
	if [ ! -z ${TLS} ]; then
		LATEST=$(curl -s curl https://api.github.com/repos/cert-manager/cert-manager/releases/latest  | jq -cr .tag_name)
		kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/${LATEST}/cert-manager.yaml
		rc=1
		tries=0
		while [ $rc -ne 0 ] && [ $tries -ne 25 ]; do
			sleep 1
			kubectl apply -f $SCRIPT_DIR/issuer.yaml
			rc=$?
			tries=$((tries+1))
		done
		if [ $rc -ne 0 ]; then
			echo "Failed to create cert-manager issuer"
			exit 1
		fi
	fi
	if [ ! -z ${PROMETHEUS} ]; then
		LATEST=$(curl -s https://api.github.com/repos/prometheus-operator/prometheus-operator/releases/latest | jq -cr .tag_name)
		curl -sL https://github.com/prometheus-operator/prometheus-operator/releases/download/${LATEST}/bundle.yaml | kubectl create -f -
		kubectl apply -f $SCRIPT_DIR/prometheus.yaml
	fi
}

OS=$(uname)

if [ "$OS" = "Darwin" ]; then
	bootcluster_macos north 1 10.60.0.0/16 10.96.0.0/16
elif [ "$OS" = "Linux" ]; then
	bootcluster_linux north 1 10.60.0.0/16 10.96.0.0/16
else
	echo "Unsupported OS"
	exit 1
fi

addons
