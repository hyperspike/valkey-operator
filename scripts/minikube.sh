#!/bin/sh

export CILIUM_CLI_MODE=classic
export SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

bootcluster() {
	name=$1
	clusterid=$2
	podcidr=$3
	servicecidr=$4
	echo "---
kind: ConfigMap
apiVersion: v1
metadata:
  name: blank-cni
  namespace: kube-system
data:
  description: This CM intentioanlly left blank to fake out minikube/kubeadm
" > blank.yaml
	minikube start --memory 4G --container-runtime=cri-o \
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
		--set enableCiliumEndpointSlice=true \
		--set ipam.operator.clusterPoolIPv4PodCIDRList=$podcidr  \
		--set ipv4NativeRoutingCIDR=10.0.0.0/8 \
		--set tunnel=disabled \
		--set tunnelProtocol="" \
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
		--set endpointStatus.enabled=true \
		--set endpointStatus.status=policy \
		--set nodePort.enabled=true \
		--set authentication.enabled=true \
		--set authentication.mutual.spire.enabled=true \
		--set authentication.mutual.spire.install.enabled=true \
		--set authentication.mutual.spire.serverAddress=spire-server.cilium-spire.svc.cluster.$name:8081 \
		--set k8sServicePort=8443 >> .cni-$name.yaml
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
	sleep 15 #@TODO build a watch loop 
	kubectl delete pod -l k8s-app=kube-dns -n kube-system
	minikube addons enable registry -p north
	# use the addon, but through a tunnel
	minikube addons enable ingress  -p north
	kubectl get svc -n ingress-nginx ingress-nginx-controller  -o yaml > .ingress.yaml
	sed -i'' -e 's/NodePort/LoadBalancer/' -e '/allocateNode/d' .ingress.yaml
	kubectl apply -f .ingress.yaml
	kubectl apply -f scripts/ingress.yaml
	kubectl delete po -n ingress-nginx -l app.kubernetes.io/component=controller
	kubectl delete pod -l k8s-app=kube-dns -n kube-system
	kubectl get deployment -n kube-system coredns -o yaml > .coredns.yaml
	sed -i'' -e 's/\(replicas:\).*/\1\ 2/' .coredns.yaml
	kubectl apply -f .coredns.yaml
	kubectl apply -f $SCRIPT_DIR/postgres-operator.yaml
}

helm repo add cilium https://helm.cilium.io/ || true
helm repo update cilium
helm pull cilium/cilium --untar

bootcluster north 1 10.60.0.0/16 10.96.0.0/16
