/*
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
*/

package controller

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"embed"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"text/template"
	"time"

	certv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmetav1 "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/google/go-cmp/cmp"
	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	valkeyClient "github.com/valkey-io/valkey-go"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	storagev1 "k8s.io/api/storage/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	hyperv1 "hyperspike.io/valkey-operator/api/v1"
	globalcfg "hyperspike.io/valkey-operator/cfg"
)

const (
	DefaultVolumeSize = "8Gi"
	Metrics           = "metrics"
	LoadBalancer      = "LoadBalancer"
	ValkeyProxy       = "valkey-proxy"
	Valkey            = "valkey"
	ValkeyPort        = 6379
	// DefaultProxyImage is the default image for the proxy
	DefaultProxyImage = "envoyproxy/envoy:v1.32.1"
)

var _ reconcile.Reconciler = &ValkeyReconciler{}

func init() {
	buf := make([]byte, 1)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		panic(fmt.Sprintf("crypto/rand is unavailable: Read() failed %#v", err))
	}
}

func randString(n int) (string, error) {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"
	ret := make([]byte, n)
	for i := 0; i < n; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return "", err
		}
		ret[i] = letters[num.Int64()]
	}

	return string(ret), nil
}

// ValkeyReconciler reconciles a Valkey object
type ValkeyReconciler struct {
	client.Client
	Recorder     record.EventRecorder
	Scheme       *runtime.Scheme
	GlobalConfig *globalcfg.Config
}

//go:embed scripts/*
var scripts embed.FS

// +kubebuilder:rbac:groups=hyperspike.io,resources=valkeys,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=hyperspike.io,resources=valkeys/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=hyperspike.io,resources=valkeys/finalizers,verbs=update
// +kubebuilder:rbac:groups=cert-manager.io,resources=clusterissuers;issuers,verbs=get;list;watch
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificates,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups="apps",resources=statefulsets;deployments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=policy,resources=poddisruptionbudgets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=storage.k8s.io,resources=storageclasses,verbs=get;list;watch
// +kubebuilder:rbac:groups=monitoring.coreos.com,resources=servicemonitors,verbs=get;list;watch;create;update;patch;delete

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the Valkey object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.18.2/pkg/reconcile
func (r *ValkeyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) { // nolint:gocyclo
	var err error
	_ = log.FromContext(ctx)

	valkey := &hyperv1.Valkey{}
	if err = r.Get(ctx, req.NamespacedName, valkey); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	err = r.validateValkeySpec(valkey)
	if err != nil {
		return ctrl.Result{}, err
	}

	if err = r.upsertConfigMap(ctx, valkey); err != nil {
		return ctrl.Result{}, err
	}
	if err = r.upsertService(ctx, valkey); err != nil {
		return ctrl.Result{}, err
	}
	if err = r.upsertServiceHeadless(ctx, valkey); err != nil {
		return ctrl.Result{}, err
	}
	if err = r.upsertServiceAccount(ctx, valkey); err != nil {
		return ctrl.Result{}, err
	}
	if valkey.Spec.Prometheus {
		if err = r.upsertServiceMonitor(ctx, valkey); err != nil {
			return ctrl.Result{}, err
		}
		if err = r.upsertMetricsService(ctx, valkey); err != nil {
			return ctrl.Result{}, err
		}
	}

	externalAccess := false
	externalType := ""
	if valkey.Spec.ExternalAccess != nil && valkey.Spec.ExternalAccess.Enabled {
		externalAccess = true
	}
	if externalAccess {
		externalType = valkey.Spec.ExternalAccess.Type
	}
	if externalAccess && externalType == LoadBalancer {
		if err := r.upsertExternalAccessLBSvc(ctx, valkey); err != nil {
			return ctrl.Result{}, err
		}
	}
	if externalAccess && externalType == "Proxy" {
		if valkey.Spec.TLS {
			if err = r.upsertProxyCertificate(ctx, valkey); err != nil {
				return ctrl.Result{}, err
			}
		}
		if err = r.upsertExternalAccessProxySecret(ctx, valkey); err != nil {
			return ctrl.Result{}, err
		}
		if err = r.upsertExternalAccessProxySvc(ctx, valkey); err != nil {
			return ctrl.Result{}, err
		}
		if err = r.upsertExternalAccessProxyDeployment(ctx, valkey); err != nil {
			return ctrl.Result{}, err
		}
	}

	if valkey.Spec.TLS {
		if err = r.upsertCertificate(ctx, valkey); err != nil {
			return ctrl.Result{}, err
		}
	}

	if !valkey.Spec.AnonymousAuth {
		_, err = r.upsertSecret(ctx, valkey, true)
		if err != nil {
			return ctrl.Result{}, err
		}
	}
	if err = r.upsertPodDisruptionBudget(ctx, valkey); err != nil {
		return ctrl.Result{}, err
	}
	if err = r.upsertStatefulSet(ctx, valkey); err != nil {
		return ctrl.Result{}, err
	}
	if err = r.initCluster(ctx, valkey); err != nil {
		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 3}, err
	}
	if err = r.checkState(ctx, valkey); err != nil {
		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 3}, nil
	}
	if externalType != LoadBalancer {
		if err := r.balanceNodes(ctx, valkey); err != nil {
			return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 5}, nil
		}
	}
	if !valkey.Status.Ready {
		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 5}, nil
	}
	if externalAccess && externalType == LoadBalancer {
		if err := r.setClusterAnnounceIp(ctx, valkey); err != nil {
			return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 5}, nil
		}
	}

	return ctrl.Result{}, nil
}

func (r *ValkeyReconciler) validateValkeySpec(valkey *hyperv1.Valkey) error {
	if valkey.Spec.Shards < 1 {
		valkey.Spec.Shards = r.GlobalConfig.Nodes
		if valkey.Spec.Shards < 1 {
			return fmt.Errorf("shards must be at least 1, got %d", valkey.Spec.Shards)
		}
	}

	if valkey.Spec.Image == "" {
		valkey.Spec.Image = r.GlobalConfig.ValkeyImage
		if valkey.Spec.Image == "" {
			return fmt.Errorf("valkey image must be specified")
		}
	}

	if valkey.Spec.ExporterImage == "" {
		valkey.Spec.ExporterImage = r.GlobalConfig.SidecarImage
	}

	if valkey.Labels == nil {
		valkey.Labels = map[string]string{}
	}
	return nil
}

func labels(valkey *hyperv1.Valkey) map[string]string {
	l := valkey.Labels
	l["app.kubernetes.io/name"] = Valkey
	l["app.kubernetes.io/instance"] = valkey.Name
	l["app.kubernetes.io/component"] = Valkey
	return l
}

func annotations(valkey *hyperv1.Valkey) map[string]string {
	return valkey.Annotations
}

func (r *ValkeyReconciler) getCACertificate(ctx context.Context, valkey *hyperv1.Valkey) (string, error) {
	logger := log.FromContext(ctx)

	cert := &certv1.Certificate{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: valkey.Namespace, Name: valkey.Name}, cert); err != nil {
		logger.Error(err, "failed to get ca certificate")
		return "", err
	}
	if cert.Status.Conditions == nil {
		return "", nil
	}
	good := false
	for _, cond := range cert.Status.Conditions {
		if cond.Type == certv1.CertificateConditionReady {
			if cond.Status == cmetav1.ConditionTrue {
				good = true
				break
			}
		}
	}
	if !good {
		return "", nil
	}
	tls := &corev1.Secret{}
	err := r.Get(ctx, types.NamespacedName{Namespace: valkey.Namespace, Name: cert.Spec.SecretName}, tls)
	if err != nil {
		logger.Error(err, "failed to get tls secret")
		return "", err
	}
	return string(tls.Data["ca.crt"]), nil
}

func (r *ValkeyReconciler) checkState(ctx context.Context, valkey *hyperv1.Valkey) error {
	logger := log.FromContext(ctx)

	initHost := fmt.Sprintf("%s.%s.svc", valkey.Name, valkey.Namespace)
	initAddress := fmt.Sprintf("%s:%d", initHost, ValkeyPort)
	vClient, err := r.getClient(ctx, valkey, initAddress, false)
	if err != nil {
		logger.Error(err, "failed to create valkey client")
		return err
	}
	defer vClient.Close()
	if err := vClient.Do(ctx, vClient.B().Ping().Build()).Error(); err != nil {
		logger.Error(err, "failed to ping valkey")
		return err
	}
	valkey.Status.Ready = true
	if err := r.Client.Status().Update(ctx, valkey); err != nil {
		logger.Error(err, "Valkey status update failed.")
		return err
	}
	return nil
}

func (r *ValkeyReconciler) upsertService(ctx context.Context, valkey *hyperv1.Valkey) error {
	logger := log.FromContext(ctx)

	logger.Info("upserting service")

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      valkey.Name,
			Namespace: valkey.Namespace,
			Labels:    labels(valkey),
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
			Ports: []corev1.ServicePort{
				{
					Name:       "tcp-valkey",
					Port:       ValkeyPort,
					TargetPort: intstr.FromString("tcp-valkey"),
					Protocol:   corev1.ProtocolTCP,
					NodePort:   0,
				},
			},
			Selector: labels(valkey),
		},
	}
	if err := controllerutil.SetControllerReference(valkey, svc, r.Scheme); err != nil {
		return err
	}
	if err := r.Create(ctx, svc); err != nil {
		if apierrors.IsAlreadyExists(err) {
			if err := r.Update(ctx, svc); err != nil {
				return err
			}
		} else {
			return err
		}
	} else {
		r.Recorder.Event(valkey, "Normal", "Created",
			fmt.Sprintf("Service %s/%s is created", valkey.Namespace, valkey.Name))
	}
	return nil
}

func (r *ValkeyReconciler) upsertConfigMap(ctx context.Context, valkey *hyperv1.Valkey) error {
	logger := log.FromContext(ctx)

	logger.Info("upserting configmap")

	defaultConfTmpl, err := scripts.ReadFile("scripts/valkey.conf")
	if err != nil {
		logger.Error(err, "failed to read valkey.conf")
		return err
	}
	confTmpl, err := template.New("valkey.conf").Parse(string(defaultConfTmpl))
	if err != nil {
		logger.Error(err, "failed to parse valkey.conf")
		return err
	}
	conf := &bytes.Buffer{}
	if err := confTmpl.Execute(conf, valkey); err != nil {
		logger.Error(err, "failed to execute valkey.conf")
		return err
	}
	pingReadinessLocal, err := scripts.ReadFile("scripts/ping_readiness_local.sh")
	if err != nil {
		logger.Error(err, "failed to read ping_readiness_local.sh")
		return err
	}
	pingLivenessLocal, err := scripts.ReadFile("scripts/ping_liveness_local.sh")
	if err != nil {
		logger.Error(err, "failed to read ping_liveness_local.sh")
		return err
	}
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      valkey.Name,
			Namespace: valkey.Namespace,
			Labels:    labels(valkey),
		},
		Data: map[string]string{
			"valkey.conf":             conf.String(),
			"ping_readiness_local.sh": string(pingReadinessLocal),
			"ping_liveness_local.sh":  string(pingLivenessLocal),
		},
	}
	if valkey.Spec.TLS {
		pingReadinessLocal, err = scripts.ReadFile("scripts/ping_readiness_local_tls.sh")
		if err != nil {
			logger.Error(err, "failed to read ping_readiness_tls.sh")
			return err
		}
		cm.Data["ping_readiness_local.sh"] = string(pingReadinessLocal)
		pingLivenessLocal, err = scripts.ReadFile("scripts/ping_liveness_local_tls.sh")
		if err != nil {
			logger.Error(err, "failed to read ping_liveness_tls.sh")
			return err
		}
		cm.Data["ping_liveness_local.sh"] = string(pingLivenessLocal)
	}
	if err := controllerutil.SetControllerReference(valkey, cm, r.Scheme); err != nil {
		return err
	}
	if err := r.Create(ctx, cm); err != nil {
		if apierrors.IsAlreadyExists(err) {
			if err := r.Update(ctx, cm); err != nil {
				logger.Error(err, "failed to update ConfigMap")
				return err
			}
		} else {
			logger.Error(err, "failed to create ConfigMap")
			return err
		}
	} else {
		r.Recorder.Event(valkey, "Normal", "Created",
			fmt.Sprintf("ConfigMap %s/%s is created", valkey.Namespace, valkey.Name))
	}
	return nil
}

func (r *ValkeyReconciler) GetPassword(ctx context.Context, valkey *hyperv1.Valkey) (string, error) {
	logger := log.FromContext(ctx)

	if valkey.Spec.ServicePassword != nil {
		return r.getServicePassword(ctx, valkey)
	}

	secret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: valkey.Namespace, Name: valkey.Name}, secret); err != nil {
		logger.Error(err, "failed to get secret")
		return "", err
	}
	return string(secret.Data["password"]), nil
}

func (r *ValkeyReconciler) buildCluster(ctx context.Context, valkey *hyperv1.Valkey) (*valkeyCluster, func(), error) {

	nodes, closeNodes, err := r.getClusterNodes(ctx, valkey)
	shards := make([]*valkeyShard, valkey.Spec.Shards)
	for i := 0; i < int(valkey.Spec.Shards); i++ {
		shards[i] = &valkeyShard{
			id:      i,
			slotMin: i * 16384 / int(valkey.Spec.Shards),
			slotMax: (i+1)*16384/int(valkey.Spec.Shards) - 1,
			nodes:   make([]*valkeyNode, 0),
		}
	}
	for _, node := range nodes {
		shards[node.shard].nodes = append(shards[node.shard].nodes, node)

	}

	cluster := &valkeyCluster{
		shards: shards,
	}

	return cluster, closeNodes, err
}

func (r *ValkeyReconciler) initCluster(ctx context.Context, valkey *hyperv1.Valkey) error { // nolint:gocyclo
	logger := log.FromContext(ctx)

	logger.Info("initializing cluster")

	cluster, closeClients, err := r.buildCluster(ctx, valkey)
	defer closeClients()
	if err != nil {
		logger.Error(err, "failed to build cluster")
		return err
	}
	if cluster == nil {
		logger.Info("cluster is nil")
		return nil
	}

	// get all connected nodes
	connectedNodes := make([]*valkeyNode, 0)
	for _, shard := range cluster.shards {
		for _, node := range shard.nodes {
			if !node.connected {
				continue
			}
			connectedNodes = append(connectedNodes, node)
		}
	}

	expectedNodeCount := int(valkey.Spec.Shards + valkey.Spec.Shards*valkey.Spec.Replicas)
	if len(connectedNodes) != expectedNodeCount {
		logger.Error(fmt.Errorf("not all nodes are connected yet, expected %d, got %d",
			expectedNodeCount, len(connectedNodes)), "not all nodes are connected yet", "expected", expectedNodeCount, "connected", len(connectedNodes))
	}

	// ensure that all nodes in the cluster are connected to each other
	for _, node := range connectedNodes {
		if !node.connected {
			continue
		}
		for _, peer := range connectedNodes {
			if node == peer {
				continue
			}
			if err = node.client.Do(ctx,
				node.client.B().ClusterMeet().Ip(peer.ip).Port(int64(peer.port)).Build()).Error(); err != nil {
				logger.Error(err, "failed to cluster meet")
				return err
			}
		}
	}

	// forget any old nodes from the cluster that are not connected
	for _, shard := range cluster.shards {
		for _, node := range shard.nodes {
			if !node.connected {
				continue
			}
			info, err := node.client.Do(ctx, node.client.B().ClusterNodes().Build()).ToString()
			if err != nil {
				logger.Error(err, "failed to fetch cluster nodes info", "node", node.name)
				return err
			}

			for _, line := range strings.Split(info, "\n") {
				line = strings.TrimPrefix(line, "txt:")
				if line == "" {
					continue
				}
				parts := strings.Split(line, " ")
				if len(parts) < 4 {
					logger.Error(fmt.Errorf("invalid cluster node info"), "incorrect parts length from cluster info",
						"line", line)
					continue
				}
				flags := strings.Split(parts[2], ",")
				if slices.Contains(flags, "myself") || slices.Contains(flags, "master") {
					continue
				}
				peerId := parts[0]
				connected := parts[7]
				if connected == "disconnected" {
					_ = node.client.Do(ctx, node.client.B().ClusterForget().NodeId(peerId).Build()).Error()
				}
			}
		}
	}

	// for each shard, check the nodes to ensure that they are configured correctly
	for _, shard := range cluster.shards {
		if len(shard.nodes) == 0 {
			continue
		}
		master := shard.nodes[0]
		for _, node := range shard.nodes {
			if node.isPrimary() {
				master = node
				break
			}
		}
		for _, node := range shard.nodes {
			if node == master {
				if node.client == nil {
					node.connected = false
					continue
				}
				var info string
				// check that the slots match that of the shard
				info, err = node.client.Do(ctx, node.client.B().ClusterNodes().Build()).ToString()
				if err != nil {
					logger.Error(err, "failed to fetch cluster info", "node", node.name)
					return err
				}

				for _, line := range strings.Split(info, "\n") {
					_ = strings.TrimPrefix(line, "txt:")
					_ = strings.TrimSuffix(line, "\r")
					if line == "" {
						continue
					}
					parts := strings.Split(line, " ")
					if len(parts) < 4 {
						logger.Error(fmt.Errorf("invalid cluster node info"),
							"incorrect parts length from cluster info",
							"line", line)
						continue
					}
					flags := strings.Split(parts[2], ",")
					if slices.Contains(flags, "myself") {
						var slotsRange string
						if len(parts) < 9 {
							slotsRange = ""
						} else {
							slotsRange = parts[8]
						}
						if slotsRange != fmt.Sprintf("%d-%d", shard.slotMin, shard.slotMax) {
							// delete any existing slot range
							_ = node.client.Do(ctx,
								node.client.B().ClusterDelslotsrange().StartSlotEndSlot().StartSlotEndSlot(0,
									16383).Build()).Error()
							// set new slot range
							err = node.client.Do(ctx,
								node.client.B().ClusterAddslotsrange().StartSlotEndSlot().StartSlotEndSlot(int64(shard.slotMin),
									int64(shard.slotMax)).Build()).Error()
							if err != nil {
								logger.Error(err, "failed to set slots range")
								return err
							}
							r.Recorder.Event(valkey, "Normal", "Setting",
								fmt.Sprintf("Set slotrange on shard %d for %s/%s", shard.id, valkey.Namespace,
									valkey.Name))
						}
					}
				}
			} else if node.primary != master.id {
				err = node.client.Do(ctx, node.client.B().ClusterReplicate().NodeId(master.id).Build()).Error()
				if err != nil {
					logger.Error(err, "failed to cluster replicate")
					return err
				}
				logger.Info("configured replica", "shard", shard.id, "node", node.name)
				r.Recorder.Event(valkey, "Normal", "Setting",
					fmt.Sprintf("Configured replica for shard %d on node %s for %s/%s", shard.id, node.name,
						valkey.Namespace,
						valkey.Name))
			}
		}
	}

	// log cluster details after init
	if len(connectedNodes) > 0 {
		vc := connectedNodes[0].client
		_ = logClusterDetails(ctx, vc)
	}

	return nil
}

func (r *ValkeyReconciler) getClusterNodes(ctx context.Context, valkey *hyperv1.Valkey) (map[string]*valkeyNode, func(), error) {
	logger := log.FromContext(ctx)

	closeFuncs := make([]func(), 0)
	closer := func() {
		for _, closeFunc := range closeFuncs {
			closeFunc()
		}
	}

	podList := &corev1.PodList{}
	if err := r.List(ctx, podList, client.InNamespace(valkey.Namespace),
		client.MatchingLabels(labels(valkey))); err != nil {
		logger.Error(err, "failed to list nodes")
		return nil, func() {}, err
	}

	nodes := make(map[string]*valkeyNode, len(podList.Items))
	for _, pod := range podList.Items {
		num, err := stsPodIndex(pod.Name)
		if err != nil {
			logger.Error(err, "failed to extract number from node name")
			return nil, func() {}, err
		}
		shard := num % int(valkey.Spec.Shards)

		nodes[pod.Name] = &valkeyNode{
			name:  pod.Name,
			shard: shard,
			ip:    pod.Status.PodIP,
		}
	}

	for _, node := range nodes {
		vc, err := r.getClient(ctx, valkey, fmt.Sprintf("%s:%d", node.ip, ValkeyPort), true)
		if err != nil {
			node.connected = false
		}
		if vc == nil {
			logger.Error(fmt.Errorf("failed to create valkey client"), "failed to create valkey client", "node", node.name)
			continue
			//return nil, closer, fmt.Errorf("failed to create valkey client")
		}
		closeFuncs = append(closeFuncs, vc.Close)
		node.client = vc

		// fetch node details
		info, err := vc.Do(ctx, vc.B().Info().Build()).ToString()
		if err != nil {
			logger.Error(err, "failed to fetch node info", "node", node.name)
			return nil, closer, err
		}

		for _, line := range strings.Split(info, "\n") {
			line = strings.TrimPrefix(line, "txt:")
			line = strings.TrimSuffix(line, "\r")
			if strings.HasPrefix(line, "# ") {
				continue
			}
			parts := strings.Split(line, ":")
			if parts[0] == "tcp_port" {
				node.port, err = strconv.Atoi(parts[1])
				if err != nil {
					logger.Error(err, "failed to parse tcp port", "node", node.name)
					return nil, closer, err
				}
			}
		}

		// fetch cluster details
		info, err = vc.Do(ctx, vc.B().ClusterNodes().Build()).ToString()
		if err != nil {
			logger.Error(err, "failed to fetch cluster nodes info", "node", node.name)
			return nil, closer, err
		}

		for _, line := range strings.Split(info, "\n") {
			line = strings.TrimPrefix(line, "txt:")
			parts := strings.Split(line, " ")
			if len(parts) < 4 {
				logger.Error(fmt.Errorf("invalid cluster node info"), "invalid cluster node info", "line", line)
				continue
			}
			flags := strings.Split(parts[2], ",")
			if slices.Contains(flags, "myself") {
				if !slices.Contains(flags, "master") {
					node.primary = parts[3]
				}
				node.id = parts[0]
				node.port = ValkeyPort
				node.flags = flags
				node.connected = true
				break
			}
		}
	}

	return nodes, closer, nil
}

// getClient returns a valkey client for the given address
func (r *ValkeyReconciler) getClient(ctx context.Context, valkey *hyperv1.Valkey, address string, single bool) (valkeyClient.Client, error) {
	logger := log.FromContext(ctx)

	opt := valkeyClient.ClientOption{
		InitAddress:       []string{address},
		ForceSingleClient: single,
	}
	if !valkey.Spec.AnonymousAuth {
		var err error
		opt.Password, err = r.GetPassword(ctx, valkey)
		if err != nil {
			logger.Error(err, "failed to get password")
			return nil, err
		}
	}

	if valkey.Spec.TLS {
		ca, err := r.getCACertificate(ctx, valkey)
		if err != nil {
			logger.Error(err, "failed to get ca certificate")
			return nil, err
		}
		if ca == "" {
			return nil, fmt.Errorf("ca certificate not ready")
		}
		certpool, err := x509.SystemCertPool()
		if err != nil {
			logger.Error(err, "failed to get system cert pool")
			return nil, err
		}
		certpool.AppendCertsFromPEM([]byte(ca))
		opt.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    certpool,
			ServerName: valkey.Name,
		}
	}
	vc, err := valkeyClient.NewClient(opt)
	if err != nil {
		logger.Error(err, "failed to create valkey client", "address", address)
		return nil, err
	}
	return vc, nil
}

func (r *ValkeyReconciler) setClusterAnnounceIp(ctx context.Context, valkey *hyperv1.Valkey) error {
	logger := log.FromContext(ctx)

	logger.Info("setting cluster announce ip")

	ips, err := r.fetchExternalIPs(ctx, valkey)
	if err != nil {
		return err
	}
	if len(ips) == 0 {
		return apierrors.NewBadRequest("external ip is empty")
	}
	clients := map[string]valkeyClient.Client{}
	for podName, ip := range ips {
		host := fmt.Sprintf("%s.%s-headless.%s.svc", podName, valkey.Name, valkey.Namespace)
		address := fmt.Sprintf("%s:%d", host, ValkeyPort)
		logger.Info("working on node", "ip", ip, "pod", podName, "address", address)
		clients[podName], err = r.getClient(ctx, valkey, address, true)
		if err != nil {
			logger.Error(err, "failed to create valkey client")
			return err
		}
		defer clients[podName].Close()
		logger.Info("setting cluster announce ip", "ip", ip, "pod", podName)
		r.Recorder.Event(valkey, "Normal", "Setting",
			fmt.Sprintf("Setting cluster announce ip %s on pod %s for %s/%s", ip, podName, valkey.Namespace, valkey.Name))

		out, err := clients[podName].Do(ctx, clients[podName].B().ConfigSet().ParameterValue().ParameterValue("cluster-announce-ip", ip).Build()).ToString()
		if err != nil {
			logger.Error(err, "failed to set cluster announce ip "+out)
			return err
		}
		cfgs, err := clients[podName].Do(ctx, clients[podName].B().ConfigGet().Parameter("cluster-announce-ip").Build()).ToMap()
		if err != nil {
			logger.Error(err, "failed to get cluster announce ip")
		}
		for k, v := range cfgs {
			str, _ := v.ToString()
			if str != ip {
				logger.Error(err, "failed to set cluster announce ip ", k, str)
			}
		}
		time.Sleep(time.Second * 1)
	}
	/* this might be useful in the future
	for podName, _ := range ips {
		for shard, shardIp := range ips {
			if shard == podName {
				continue
			}
			time.Sleep(time.Second * 1)
			logger.Info("node meeting peer", "peer", shardIp, "pod", podName)
			r.Recorder.Event(valkey, "Normal", "Setting",
				fmt.Sprintf("Node meeting peer %s on pod %s for %s/%s", shardIp, podName, valkey.Namespace, valkey.Name))
			if err := clients[podName].Do(ctx, clients[podName].B().ClusterMeet().Ip(shardIp).Port(6379).Build()).Error(); err != nil {
				logger.Error(err, "failed to cluster meet", "shard", shard, "ip", shardIp, "pod", podName)
			}
		}
	}
	*/
	return nil
}

func (r *ValkeyReconciler) fetchExternalIPs(ctx context.Context, valkey *hyperv1.Valkey) (map[string]string, error) {
	logger := log.FromContext(ctx)

	ips := map[string]string{}
	svcs := &corev1.ServiceList{}
	if err := r.List(ctx, svcs, client.InNamespace(valkey.Namespace)); err != nil {
		logger.Error(err, "failed to list services")
		return nil, err
	}
	for _, svc := range svcs.Items {
		if svc.Labels["app.kubernetes.io/component"] == "valkey-external" && svc.Labels["app.kubernetes.io/instance"] == valkey.Name {
			podName := strings.ReplaceAll(svc.Name, "-external", "")
			if len(svc.Status.LoadBalancer.Ingress) == 0 {
				logger.Info("external ip is empty")
				return nil, nil
			}
			ip := svc.Status.LoadBalancer.Ingress[0].IP
			if ip == "" {
				logger.Info("external ip is empty")
				return nil, nil
			}
			logger.Info("external ip", "pod", podName, "ip", ip)
			ips[podName] = ip
		}
	}
	return ips, nil
}

func (r *ValkeyReconciler) upsertExternalAccessLBSvc(ctx context.Context, valkey *hyperv1.Valkey) error {
	logger := log.FromContext(ctx)

	logger.Info("upserting external access (NodePort/LoadBalancer)")

	for i := 0; i < int(valkey.Spec.Shards); i++ {
		selectorLabels := labels(valkey)
		selectorLabels["apps.kubernetes.io/pod-index"] = fmt.Sprintf("%d", i)
		svcLabels := labels(valkey)
		svcLabels["app.kubernetes.io/component"] = "valkey-external"
		svc := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("%s-external-%d", valkey.Name, i),
				Namespace: valkey.Namespace,
				Labels:    svcLabels,
			},
			Spec: corev1.ServiceSpec{
				Type: corev1.ServiceType(valkey.Spec.ExternalAccess.Type),
				Ports: []corev1.ServicePort{
					{
						Name:       "tcp-valkey",
						Port:       ValkeyPort,
						TargetPort: intstr.FromString("tcp-valkey"),
						Protocol:   corev1.ProtocolTCP,
					},
					{
						Name:       "tcp-valkey-bus",
						Port:       16379,
						TargetPort: intstr.FromString("tcp-valkey-bus"),
						Protocol:   corev1.ProtocolTCP,
					},
				},
				Selector: selectorLabels,
			},
		}
		if valkey.Spec.ExternalAccess.LoadBalancer != nil && len(valkey.Spec.ExternalAccess.LoadBalancer.Annotations) > 0 {
			svc.Annotations = valkey.Spec.ExternalAccess.LoadBalancer.Annotations
		}

		if err := controllerutil.SetControllerReference(valkey, svc, r.Scheme); err != nil {
			return err
		}
		if err := r.Create(ctx, svc); err != nil {
			if apierrors.IsAlreadyExists(err) {
				if err := r.Update(ctx, svc); err != nil {
					logger.Error(err, "failed to update external access svc")
					return err
				}
			} else {
				logger.Error(err, "failed to create external access svc")
				return err
			}
		} else {
			r.Recorder.Event(valkey, "Normal", "Created",
				fmt.Sprintf("Service %s/%s is created", valkey.Namespace, valkey.Name+"-external"))
		}
	}
	return nil
}

func (r *ValkeyReconciler) upsertExternalAccessProxySvc(ctx context.Context, valkey *hyperv1.Valkey) error {
	logger := log.FromContext(ctx)

	logger.Info("upserting external proxy load balancer service")

	proxyLabels := labels(valkey)
	proxyLabels["app.kubernetes.io/component"] = ValkeyProxy
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      valkey.Name + "-proxy",
			Namespace: valkey.Namespace,
			Labels:    proxyLabels,
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeLoadBalancer,
			Ports: []corev1.ServicePort{
				{
					Name:       "tcp-valkey",
					Port:       ValkeyPort,
					TargetPort: intstr.FromString("tcp-valkey"),
					Protocol:   corev1.ProtocolTCP,
				},
			},
			Selector: proxyLabels,
		},
	}
	if valkey.Spec.ExternalAccess.Proxy != nil && valkey.Spec.ExternalAccess.Proxy.Annotations != nil && len(valkey.Spec.ExternalAccess.Proxy.Annotations) > 0 {
		svc.Annotations = valkey.Spec.ExternalAccess.Proxy.Annotations
	}
	if err := controllerutil.SetControllerReference(valkey, svc, r.Scheme); err != nil {
		return err
	}
	if err := r.Create(ctx, svc); err != nil {
		if apierrors.IsAlreadyExists(err) {
			if err := r.Update(ctx, svc); err != nil {
				logger.Error(err, "failed to update external proxy svc")
				return err
			}
		} else {
			logger.Error(err, "failed to create external proxy svc")
			return err
		}
	} else {
		r.Recorder.Event(valkey, "Normal", "Created",
			fmt.Sprintf("Service %s/%s is created", valkey.Namespace, valkey.Name+"-proxy"))
	}
	return nil
}

func (r *ValkeyReconciler) upsertProxyCertificate(ctx context.Context, valkey *hyperv1.Valkey) error {
	logger := log.FromContext(ctx)

	logger.Info("upserting proxy certificate")

	issuerName := ""
	issuerKind := ""
	if valkey.Spec.ExternalAccess != nil {
		issuerName = valkey.Spec.ExternalAccess.CertIssuer
		issuerKind = valkey.Spec.ExternalAccess.CertIssuerType
	}
	if issuerKind == "" {
		issuerKind = valkey.Spec.CertIssuerType
	}
	if issuerName == "" {
		issuerName = valkey.Spec.CertIssuer
	}
	cert := &certv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      valkey.Name + "-proxy",
			Namespace: valkey.Namespace,
			Labels:    labels(valkey),
		},
		Spec: certv1.CertificateSpec{
			SecretName: valkey.Name + "-proxy-tls",
			IssuerRef: cmetav1.ObjectReference{
				Name: issuerName,
				Kind: issuerKind,
			},
			CommonName: valkey.Name + "-proxy",
			DNSNames: []string{
				valkey.Name + "-proxy",
				valkey.Name + "-proxy." + valkey.Namespace,
				valkey.Name + "-proxy." + valkey.Namespace + ".svc",
				valkey.Name + "-proxy." + valkey.Namespace + ".svc." + valkey.Spec.ClusterDomain,
			},
		},
	}
	hostname := valkey.Spec.ExternalAccess.Proxy.Hostname
	if hostname != "" {
		cert.Spec.DNSNames = append(cert.Spec.DNSNames, hostname)
	}
	if err := controllerutil.SetControllerReference(valkey, cert, r.Scheme); err != nil {
		return err
	}
	if err := r.Create(ctx, cert); err != nil {
		if apierrors.IsAlreadyExists(err) {
			if err := r.Update(ctx, cert); err != nil {
				logger.Error(err, "failed to update proxy certificate")
				return err
			}
		} else {
			logger.Error(err, "failed to create proxy certificate")
			return err
		}
	} else {
		r.Recorder.Event(valkey, "Normal", "Created",
			fmt.Sprintf("Certificate %s/%s is created", valkey.Namespace, valkey.Name+"-proxy-cert"))
	}
	return nil
}

func (r *ValkeyReconciler) upsertExternalAccessProxySecret(ctx context.Context, valkey *hyperv1.Valkey) error {
	logger := log.FromContext(ctx)

	logger.Info("upserting external proxy configmap")

	endpoints := []string{}
	for i := 0; i < int(valkey.Spec.Shards); i++ {
		host := fmt.Sprintf("%s-%d.%s-headless.%s.svc", valkey.Name, i, valkey.Name, valkey.Namespace)
		endpoints = append(endpoints, `        - endpoint:
            address:
              socket_address:
                address: `+host+`
                port_value: `+fmt.Sprintf("%d", ValkeyPort))
	}
	tlsServer := ""
	tlsClient := ""
	if valkey.Spec.TLS {
		tlsServer = `      transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
          #require_client_certificate: true # @TODO mtls auth
          common_tls_context:
            tls_certificates:
            - certificate_chain:
                filename: /etc/envoy/certs/tls.crt
              private_key:
                filename: /etc/envoy/certs/tls.key
            validation_context:
              trusted_ca:
                filename: /etc/envoy/certs/ca.crt`
		tlsClient = `    transport_socket:
      name: envoy.transport_sockets.tls
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
        common_tls_context:
          #tls_certificates:
          #  certificate_chain:
          #    filename: "certs/client.crt"
          #  private_key:
          #    filename: "/etc/valkey/certs/client.key"
          validation_context:
            trusted_ca:
              filename: "/etc/valkey/certs/ca.crt"`
	}
	upstreamPassword := ""
	downstreamPassword := ""
	if !valkey.Spec.AnonymousAuth {
		password, err := r.GetPassword(ctx, valkey)
		if err != nil {
			logger.Error(err, "failed to get password")
			return err
		}
		downstreamPassword = `          downstream_auth_password:
            inline_string: "` + password + `"`
		upstreamPassword = `            inline_string: "` + password + `"`
	}
	proxyLabels := labels(valkey)
	proxyLabels["app.kubernetes.io/component"] = ValkeyProxy
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      valkey.Name + "-proxy",
			Namespace: valkey.Namespace,
			Labels:    proxyLabels,
		},
		Data: map[string][]byte{
			"envoy.yaml": []byte(`
static_resources:
  listeners:
  - name: redis_listener
    address:
      socket_address:
        address: 0.0.0.0
        port_value: ` + fmt.Sprintf("%d", ValkeyPort) + `
    filter_chains:
    - filters:
      - name: envoy.filters.network.redis_proxy
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.redis_proxy.v3.RedisProxy
          stat_prefix: egress_redis
          settings:
            op_timeout: 5s
            enable_redirection: false
          prefix_routes:
            catch_all_route:
              cluster: redis_cluster
` + downstreamPassword + `
` + tlsServer + `
  clusters:
  - name: redis_cluster
    # type: STRICT_DNS  # static
    lb_policy: CLUSTER_PROVIDED
    load_assignment:
      cluster_name: redis_cluster
      endpoints:
      - lb_endpoints:
` + strings.Join(endpoints, "\n") + `
    cluster_type:
      name: envoy.clusters.redis
      typed_config:
        "@type": type.googleapis.com/google.protobuf.Struct
        value:
          cluster_refresh_rate: 1s
          cluster_refresh_timeout: 4s
    typed_extension_protocol_options:
      envoy.filters.network.redis_proxy:
        "@type": type.googleapis.com/google.protobuf.Struct
        value:
          auth_password:
` + upstreamPassword + `
` + tlsClient + `
admin:
  address:
    socket_address:
      address: 0.0.0.0
      port_value: 8001
`),
		},
	}

	if err := controllerutil.SetControllerReference(valkey, secret, r.Scheme); err != nil {
		return err
	}
	if err := r.Create(ctx, secret); err != nil {
		if apierrors.IsAlreadyExists(err) {
			if err := r.Update(ctx, secret); err != nil {
				logger.Error(err, "failed to update external proxy secret")
				return err
			}
		} else {
			logger.Error(err, "failed to create external proxy configmap")
		}
	} else {
		r.Recorder.Event(valkey, "Normal", "Created",
			fmt.Sprintf("ConfigMap %s/%s is created", valkey.Namespace, valkey.Name+"-proxy"))
	}
	return nil
}

func (r *ValkeyReconciler) upsertExternalAccessProxyDeployment(ctx context.Context, valkey *hyperv1.Valkey) error {
	logger := log.FromContext(ctx)

	logger.Info("upserting external proxy deployment")

	proxyLabels := labels(valkey)
	proxyLabels["app.kubernetes.io/component"] = ValkeyProxy

	proxyEnvoyConfigMap := valkey.Name + "-proxy"

	replicas := int32(1)
	if valkey.Spec.ExternalAccess.Proxy != nil && valkey.Spec.ExternalAccess.Proxy.Replicas != nil {
		replicas = *valkey.Spec.ExternalAccess.Proxy.Replicas
	}
	image := DefaultProxyImage
	if valkey.Spec.ExternalAccess.Proxy != nil && valkey.Spec.ExternalAccess.Proxy.Image != "" {
		image = valkey.Spec.ExternalAccess.Proxy.Image
	}
	proxyDeployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      valkey.Name + "-proxy",
			Namespace: valkey.Namespace,
			Labels:    proxyLabels,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: proxyLabels,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: proxyLabels,
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "envoy",
							Image: image,
							Args: []string{
								"-c", "/etc/envoy.yaml",
							},
							Ports: []corev1.ContainerPort{
								{
									Name:          "tcp-valkey",
									ContainerPort: ValkeyPort,
									Protocol:      corev1.ProtocolTCP,
								},
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "envoy-config",
									MountPath: "/etc/envoy.yaml",
									SubPath:   "envoy.yaml",
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "envoy-config",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: proxyEnvoyConfigMap,
								},
							},
						},
					},
				},
			},
		},
	}
	if valkey.Spec.TLS {
		proxyDeployment.Spec.Template.Spec.Containers[0].VolumeMounts = append(proxyDeployment.Spec.Template.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{
			Name:      "envoy-certs",
			MountPath: "/etc/envoy/certs",
		})
		proxyDeployment.Spec.Template.Spec.Volumes = append(proxyDeployment.Spec.Template.Spec.Volumes, corev1.Volume{
			Name: "envoy-certs",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: valkey.Name + "-proxy-tls",
				},
			},
		})
		proxyDeployment.Spec.Template.Spec.Containers[0].VolumeMounts = append(proxyDeployment.Spec.Template.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{
			Name:      "valkey-certs",
			MountPath: "/etc/valkey/certs",
		})
		proxyDeployment.Spec.Template.Spec.Volumes = append(proxyDeployment.Spec.Template.Spec.Volumes, corev1.Volume{
			Name: "valkey-certs",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: valkey.Name + "-tls",
				},
			},
		})
	}

	if err := controllerutil.SetControllerReference(valkey, proxyDeployment, r.Scheme); err != nil {
		return err
	}
	if err := r.Create(ctx, proxyDeployment); err != nil {
		if apierrors.IsAlreadyExists(err) {
			if err := r.Update(ctx, proxyDeployment); err != nil {
				logger.Error(err, "failed to update external proxy deployment")
				return err
			}
		} else {
			logger.Error(err, "failed to create external proxy deployment")
			return err
		}
	} else {
		r.Recorder.Event(valkey, "Normal", "Created",
			fmt.Sprintf("Deployment %s/%s is created", valkey.Namespace, valkey.Name+"-proxy"))
	}
	return nil
}

func (r *ValkeyReconciler) upsertServiceHeadless(ctx context.Context, valkey *hyperv1.Valkey) error {
	logger := log.FromContext(ctx)

	logger.Info("upserting service")

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      valkey.Name + "-headless",
			Namespace: valkey.Namespace,
			Labels:    labels(valkey),
		},
		Spec: corev1.ServiceSpec{
			Type:                     corev1.ServiceTypeClusterIP,
			ClusterIP:                "None",
			PublishNotReadyAddresses: true,
			Ports: []corev1.ServicePort{
				{
					Name:       "tcp-valkey",
					Port:       ValkeyPort,
					TargetPort: intstr.FromString("tcp-valkey"),
				},
				{
					Name:       "tcp-valkey-bus",
					Port:       16379,
					TargetPort: intstr.FromString("tcp-valkey-bus"),
				},
			},
			Selector: labels(valkey),
		},
	}
	if err := controllerutil.SetControllerReference(valkey, svc, r.Scheme); err != nil {
		return err
	}
	if err := r.Create(ctx, svc); err != nil {
		if apierrors.IsAlreadyExists(err) {
			if err := r.Update(ctx, svc); err != nil {
				logger.Error(err, "failed to update service")
				return err
			}
		} else {
			logger.Error(err, "failed to create service")
			return err
		}
	} else {
		r.Recorder.Event(valkey, "Normal", "Created",
			fmt.Sprintf("Service %s/%s is created", valkey.Namespace, valkey.Name+"-headless"))
	}
	return nil
}

func (r *ValkeyReconciler) upsertMetricsService(ctx context.Context, valkey *hyperv1.Valkey) error {
	logger := log.FromContext(ctx)

	logger.Info("upserting metrics service")

	l := labels(valkey)
	l["app.kubernetes.io/component"] = Metrics

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      valkey.Name + "-metrics",
			Namespace: valkey.Namespace,
			Labels:    l,
		},
		Spec: corev1.ServiceSpec{
			Type:      corev1.ServiceTypeClusterIP,
			ClusterIP: "None",
			// Omit the publishNotReadyAddresses field as this is metrics!
			Ports: []corev1.ServicePort{
				{
					Name:       "valkey-metrics",
					Port:       9121,
					TargetPort: intstr.FromString("valkey-metrics"),
					Protocol:   corev1.ProtocolTCP,
				},
			},
			Selector: labels(valkey),
		},
	}
	if err := controllerutil.SetControllerReference(valkey, svc, r.Scheme); err != nil {
		return err
	}
	if err := r.Create(ctx, svc); err != nil {
		if apierrors.IsAlreadyExists(err) {
			if err := r.Update(ctx, svc); err != nil {
				logger.Error(err, "failed to update metrics service")
				return err
			}
		} else {
			logger.Error(err, "failed to create metrics service")
			return err
		}
	} else {
		r.Recorder.Event(valkey, "Normal", "Created",
			fmt.Sprintf("Service %s/%s is created", valkey.Namespace, valkey.Name+"-metrics"))
	}
	return nil
}

func (r *ValkeyReconciler) upsertServiceMonitor(ctx context.Context, valkey *hyperv1.Valkey) error {
	logger := log.FromContext(ctx)

	logger.Info("upserting prometheus service monitor")

	labelSelector := labels(valkey)
	labelSelector["app.kubernetes.io/component"] = Metrics
	l := labels(valkey)
	l["app.kubernetes.io/component"] = Metrics
	for k, v := range valkey.Spec.PrometheusLabels {
		l[k] = v
	}

	sm := &monitoringv1.ServiceMonitor{
		ObjectMeta: metav1.ObjectMeta{
			Name:      valkey.Name,
			Namespace: valkey.Namespace,
			Labels:    l,
		},
		Spec: monitoringv1.ServiceMonitorSpec{
			Selector: metav1.LabelSelector{
				MatchLabels: labelSelector,
			},
			Endpoints: []monitoringv1.Endpoint{
				{
					Port: "valkey-metrics",
				},
			},
		},
	}
	if err := controllerutil.SetControllerReference(valkey, sm, r.Scheme); err != nil {
		return err
	}
	err := r.Get(ctx, types.NamespacedName{Namespace: valkey.Namespace, Name: valkey.Name}, sm)
	if err != nil && apierrors.IsNotFound(err) {
		if err := r.Create(ctx, sm); err != nil {
			logger.Error(err, "failed to create prometheus service monitor")
			return err
		}
		r.Recorder.Event(valkey, "Normal", "Created",
			fmt.Sprintf("ServiceMonitor %s/%s is created", valkey.Namespace, valkey.Name))
	} else if err != nil {
		logger.Error(err, "failed to fetch prometheus service monitor")
		return err
	} else if err == nil && false { // detect changes
		// updates here
		if err := r.Update(ctx, sm); err != nil {
			logger.Error(err, "failed to update prometheus service monitor")
			return err
		}
	}
	return nil
}

func (r *ValkeyReconciler) upsertCertificate(ctx context.Context, valkey *hyperv1.Valkey) error {
	logger := log.FromContext(ctx)

	logger.Info("upserting certificate")

	clusterDomain, err := r.detectClusterDomain(ctx, valkey)
	if err != nil {
		logger.Error(err, "failed to detect cluster domain")
		return err
	}
	logger.Info("using cluster domain " + clusterDomain)
	issuer := valkey.Spec.CertIssuer
	issuerType := valkey.Spec.CertIssuerType
	cert := &certv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      valkey.Name,
			Namespace: valkey.Namespace,
			Labels:    labels(valkey),
		},
		Spec: certv1.CertificateSpec{
			CommonName: valkey.Name + "." + valkey.Namespace + ".svc",
			SecretName: valkey.Name + "-tls",
			IssuerRef: cmetav1.ObjectReference{
				Name: issuer,
				Kind: issuerType,
			},
			DNSNames: []string{
				"localhost",
				valkey.Name,
				valkey.Name + "." + valkey.Namespace + ".svc",
				valkey.Name + "." + valkey.Namespace + ".svc." + clusterDomain,
				valkey.Name + "-headless",
				valkey.Name + "-headless." + valkey.Namespace + ".svc",
				valkey.Name + "-headless." + valkey.Namespace + ".svc." + clusterDomain,
				"*." + valkey.Name + "-headless." + valkey.Namespace + ".svc",
				"*." + valkey.Name + "-headless." + valkey.Namespace + ".svc." + clusterDomain,
			},
			IPAddresses: []string{
				"127.0.0.1",
			},
		},
	}

	if err := controllerutil.SetControllerReference(valkey, cert, r.Scheme); err != nil {
		return err
	}
	err = r.Get(ctx, types.NamespacedName{Namespace: valkey.Namespace, Name: valkey.Name}, cert)
	if err != nil && apierrors.IsNotFound(err) {
		if err := r.Create(ctx, cert); err != nil {
			logger.Error(err, "failed to create certificate")
			return err
		}
		r.Recorder.Event(valkey, "Normal", "Created",
			fmt.Sprintf("Certificate %s/%s is created", valkey.Namespace, valkey.Name))
	} else if err != nil {
		logger.Error(err, "failed to fetch certificate")
		return err
	} else if err == nil && false { // detect changes
		if err := r.Update(ctx, cert); err != nil {
			logger.Error(err, "failed to update certificate")
			return err
		}
	}

	return nil
}

func getServicePasswordKey(valkey *hyperv1.Valkey) string {
	if valkey.Spec.ServicePassword == nil {
		return "password"
	}
	return valkey.Spec.ServicePassword.Key
}

func getServicePasswordName(valkey *hyperv1.Valkey) string {
	if valkey.Spec.ServicePassword == nil {
		return valkey.Name
	}
	return valkey.Spec.ServicePassword.Name
}

func (r *ValkeyReconciler) getServicePassword(ctx context.Context, valkey *hyperv1.Valkey) (string, error) {
	logger := log.FromContext(ctx)

	secret := &corev1.Secret{}
	err := r.Get(ctx, types.NamespacedName{Namespace: valkey.Namespace, Name: getServicePasswordName(valkey)}, secret)
	if err != nil {
		logger.Error(err, "failed to fetch secret", "name", getServicePasswordName(valkey))
		return "", err
	}
	if secret.Data == nil {
		return "", fmt.Errorf("secret %s/%s is empty", valkey.Namespace, getServicePasswordName(valkey))
	}
	if secret.Data[getServicePasswordKey(valkey)] == nil {
		return "", fmt.Errorf("key %s is empty in secret %s/%s", getServicePasswordKey(valkey), valkey.Namespace, getServicePasswordName(valkey))
	}
	return string(secret.Data[getServicePasswordKey(valkey)]), nil
}

func (r *ValkeyReconciler) upsertSecret(ctx context.Context, valkey *hyperv1.Valkey, once bool) (string, error) {
	logger := log.FromContext(ctx)

	if valkey.Spec.ServicePassword != nil {
		return r.getServicePassword(ctx, valkey)
	}

	logger.Info("upserting secret")
	rs, err := randString(16)
	if err != nil {
		return "", err
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      valkey.Name,
			Namespace: valkey.Namespace,
			Labels:    labels(valkey),
		},
		Data: map[string][]byte{
			"password": []byte(rs),
		},
	}
	if err := controllerutil.SetControllerReference(valkey, secret, r.Scheme); err != nil {
		return "", err
	}
	err = r.Get(ctx, types.NamespacedName{Namespace: valkey.Namespace, Name: valkey.Name}, secret)
	if err != nil && apierrors.IsNotFound(err) {
		if err := r.Create(ctx, secret); err != nil {
			logger.Error(err, "failed to update secret")
			return "", err
		}
		r.Recorder.Event(valkey, "Normal", "Created",
			fmt.Sprintf("Secret %s/%s is created", valkey.Namespace, valkey.Name))
	} else if err == nil && !once {
		if err := r.Update(ctx, secret); err != nil {
			logger.Error(err, "failed to create secret")
			return "", err
		}
	} else if err != nil {
		logger.Error(err, "failed fetching secret")
		return "", err
	}
	return string(secret.Data["password"]), nil
}

func (r *ValkeyReconciler) upsertServiceAccount(ctx context.Context, valkey *hyperv1.Valkey) error {
	logger := log.FromContext(ctx)

	logger.Info("upserting service account")
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      valkey.Name,
			Namespace: valkey.Namespace,
			Labels:    labels(valkey),
		},
	}
	if err := controllerutil.SetControllerReference(valkey, sa, r.Scheme); err != nil {
		return err
	}
	if err := r.Create(ctx, sa); err != nil {
		if errors.IsAlreadyExists(err) {
			// Get existing resource
			existingSA := &corev1.ServiceAccount{}
			if err := r.Get(ctx, types.NamespacedName{Namespace: valkey.Namespace, Name: valkey.Name}, existingSA); err != nil {
				logger.Error(err, "failed to get existing service account")
				return err
			}

			// Check if changes are needed
			desiredLabels := labels(valkey)
			labelsChanged := !labelsContains(existingSA.Labels, desiredLabels)
			hasControllerRef := hasValkeyControllerReferences(existingSA.OwnerReferences, sa.OwnerReferences)

			// Skip patch if no changes needed
			if !labelsChanged && hasControllerRef {
				logger.Info("service account already up to date, skipping patch")
				return nil
			}

			// Create patch only if changes are needed
			patch := client.MergeFrom(existingSA.DeepCopy())

			// Update labels if changed
			if labelsChanged {
				existingSA.Labels = mergeLabels(existingSA.Labels, desiredLabels)
			}

			// Add controller reference if missing
			if !hasControllerRef {
				if err := controllerutil.SetControllerReference(valkey, existingSA, r.Scheme); err != nil {
					logger.Error(err, "failed to set controller reference")
					return err
				}
			}

			// Apply patch
			if err := r.Patch(ctx, existingSA, patch); err != nil {
				logger.Error(err, "failed to patch service account")
				return err
			}
		} else {
			logger.Error(err, "failed to create service account")
			return err
		}
	} else {
		r.Recorder.Event(valkey, "Normal", "Created",
			fmt.Sprintf("ServiceAccount %s/%s is created", valkey.Namespace, valkey.Name))
	}
	return nil
}

func removePort(addr string) string {
	if strings.Contains(addr, ":") {
		return strings.Split(addr, ":")[0]
	}
	return addr
}

func labelsContains(existing, desired map[string]string) bool {
	for k, v := range desired {
		if existing[k] != v {
			return false
		}
	}
	return true
}

func mergeLabels(existing, desired map[string]string) map[string]string {
	if existing == nil {
		existing = make(map[string]string)
	}
	for k, v := range desired {
		existing[k] = v
	}
	return existing
}

func hasValkeyControllerReferences(ownerRefs []metav1.OwnerReference, valkeyRefs []metav1.OwnerReference) bool {
	for _, valkeyRef := range valkeyRefs {
		if !hasValkeyControllerReference(ownerRefs, valkeyRef) {
			return false
		}
	}
	return true
}

// Compare the owner references of the Valkey resource with the provided reference
// to determine if the Valkey controller is already set as an owner.
// This method does not check for the controller field, as it is not set by default and may modified by other controllers.
func hasValkeyControllerReference(ownerRefs []metav1.OwnerReference, valkeyRef metav1.OwnerReference) bool {
	for _, ref := range ownerRefs {
		if ref.APIVersion == valkeyRef.APIVersion &&
			ref.Kind == valkeyRef.Kind &&
			ref.Name == valkeyRef.Name {
			return true
		}
	}

	return false
}

func (r *ValkeyReconciler) balanceNodes(ctx context.Context, valkey *hyperv1.Valkey) error { // nolint: gocyclo
	logger := log.FromContext(ctx)

	// connect to the first node!
	initHost := fmt.Sprintf("%s-0.%s-headless.%s.svc", valkey.Name, valkey.Name, valkey.Namespace)
	initAddress := fmt.Sprintf("%s:%d", initHost, ValkeyPort)
	vClient, err := r.getClient(ctx, valkey, initAddress, false)
	if err != nil {
		logger.Error(err, "failed to create valkey client")
		return err
	}
	defer vClient.Close()
	if err := vClient.Do(ctx, vClient.B().Ping().Build()).Error(); err != nil {
		logger.Error(err, "failed to ping valkey")
		return err
	}

	logger.Info("balancing nodes")
	nodes, err := vClient.Do(ctx, vClient.B().ClusterNodes().Build()).ToString()
	if err != nil {
		logger.Error(err, "failed to get nodes")
		return err
	}
	ids := map[string]string{}
	for _, node := range strings.Split(nodes, "\n") {
		if node == "" {
			continue
		}
		line := strings.Split(node, " ")
		id := strings.ReplaceAll(line[0], "txt:", "")
		addr := removePort(line[1])
		/*
			addrs, err := net.LookupAddr(addr)
			if err != nil {
				logger.Error(err, "failed to lookup addr", "valkey", valkey.Name, "namespace", valkey.Namespace, "addr", addr)
				continue
			}
			ip := strings.Split(addrs[0], ".")[0]
		*/
		//namespace := strings.Split(addrs[0], ".")[1]
		ids[addr] = id
	}
	pods := map[string]string{}
	var tries int
	expectedPodsLen := int(valkey.Spec.Shards * (valkey.Spec.Replicas + 1))
	for {
		if len(pods) != expectedPodsLen {
			pods, err = r.getPodIPs(ctx, valkey)
			if err != nil {
				logger.Error(err, "failed to get pod ips")
				return err
			}
			time.Sleep(time.Second * 2)
			tries++
			if tries > 15 {
				err := fmt.Errorf("timeout waiting for pods")
				logger.Error(err, "failed to get pod ips")
				return err
			}
		} else {
			break
		}
	}

	myid, err := vClient.Do(ctx, vClient.B().ClusterMyid().Build()).ToString()
	if err != nil {
		logger.Error(err, "failed to get myid")
		return err
	}
	for ipId, id := range ids {
		found := false
		for ipPod := range pods {
			if ipId == ipPod {
				found = true
				break
			}
		}
		if !found {
			if myid == id {
				continue
			}
			if err := vClient.Do(ctx, vClient.B().ClusterForget().NodeId(id).Build()).Error(); err != nil {
				logger.Error(err, "failed to forget node "+ipId+"/"+id)
				return err
			}
			r.Recorder.Event(valkey, "Normal", "Updated", fmt.Sprintf("Node %s removed from %s/%s", ipId, valkey.Namespace, valkey.Name))
		}
	}
	for ipPod, pod := range pods {
		found := false
		for ipId := range ids {
			if ipPod == ipId {
				found = true
				break
			}
		}
		if !found {
			var dial int
			for {
				network, err := net.Dial("tcp", ipPod+":"+fmt.Sprintf("%d", ValkeyPort))
				if err != nil {
					if err := network.Close(); err != nil {
						logger.Error(err, "failed to close network")
					}
					time.Sleep(time.Second * 2)
					dial++
					if dial > 60 {
						logger.Error(err, "failed to dial")
						break
					}
					continue
				}
				if network != nil {
					if err := network.Close(); err != nil {
						logger.Error(err, "failed to close network")
					}
				} else {
					time.Sleep(time.Second * 2)
					dial++
					if dial > 60 {
						logger.Error(err, "failed to dial")
						break
					}
					continue
				}
				break
			}
			if dial > 60 {
				logger.Error(err, "failed to dial")
				continue
			}
			res, err := vClient.Do(ctx, vClient.B().ClusterMeet().Ip(ipPod).Port(ValkeyPort).Build()).ToString()
			logger.Info("meeting node "+res, "node", pod)
			if err != nil {
				logger.Error(err, "failed to meet node", "node", pod)
				return err
			}
			r.Recorder.Event(valkey, "Normal", "Updated", fmt.Sprintf("Node %s added to %s/%s", pod, valkey.Namespace, valkey.Name))
		}
	}

	return nil
}

func (r *ValkeyReconciler) getPodIPs(ctx context.Context, valkey *hyperv1.Valkey) (map[string]string, error) {
	logger := log.FromContext(ctx)

	pods := &corev1.PodList{}
	if err := r.List(ctx, pods, client.InNamespace(valkey.Namespace), client.MatchingLabels(labels(valkey))); err != nil {
		logger.Error(err, "failed to list pods")
		return nil, err
	}
	ret := map[string]string{}
	for _, pod := range pods.Items {
		ret[pod.Status.PodIP] = pod.Name + "." + valkey.Name + "-headless." + valkey.Namespace + ".svc"
	}
	return ret, nil
}

func (r *ValkeyReconciler) getCertManagerIp(ctx context.Context) (string, error) {
	logger := log.FromContext(ctx)
	pods := &corev1.PodList{}
	l := map[string]string{
		"app.kubernetes.io/component": "controller",
	}
	if err := r.List(ctx, pods, client.InNamespace("cert-manager"), client.MatchingLabels(l)); err != nil {
		logger.Error(err, "failed to list coredns pods")
		return "", err
	}
	for _, pod := range pods.Items {
		return pod.Status.PodIP, nil
	}
	return "", nil
}

func (r *ValkeyReconciler) detectClusterDomain(ctx context.Context, valkey *hyperv1.Valkey) (string, error) {
	logger := log.FromContext(ctx)

	logger.Info("detecting cluster domain")
	if valkey.Spec.ClusterDomain != "" {
		return valkey.Spec.ClusterDomain, nil
	}

	clusterDomain := os.Getenv("CLUSTER_DOMAIN")
	if clusterDomain == "" {
		clusterDomain = "cluster.local"
	}
	ip, err := r.getCertManagerIp(ctx)
	if err != nil {
		return "", err
	}

	if ip != "" {
		addrs, err := net.LookupAddr(ip)
		if err != nil {
			logger.Error(err, "failed to lookup addr", "ip", ip)
		} else {
			logger.Info("detected addrs", "addrs", addrs)
			clusterDomain = addrs[0]
			clusterDomain = clusterDomain[strings.Index(clusterDomain, ".svc.")+5:]
			clusterDomain = strings.TrimSuffix(clusterDomain, ".")
			logger.Info("detected cluster domain", "clusterDomain", clusterDomain)
		}
	}
	valkey.Spec.ClusterDomain = clusterDomain
	if err := r.Update(ctx, valkey); err != nil {
		logger.Error(err, "failed to update valkey")
		return "", err
	}
	return clusterDomain, nil
}

/*
func (r *ValkeyReconciler) getPodIp(ctx context.Context, name, namespace string) (string, error) {
	logger := log.FromContext(ctx)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
	}
	if err := r.waitForPod(ctx, name, namespace); err != nil {
		return "", err
	}

	if err := r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, pod); err != nil {
		logger.Error(err, "failed fetching pod", "name", name, "namespace", namespace)
		return "", err
	}
	return pod.Status.PodIP, nil
}

func (r *ValkeyReconciler) waitForPod(ctx context.Context, name, namespace string) error {
	logger := log.FromContext(ctx)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
	}
	var tries int
	for {
		if err := r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, pod); err != nil {
			logger.Error(err, "failed fetching pod", "name", name, "namespace", namespace)
			continue
		}
		if pod.Status.Phase == corev1.PodRunning {
			break
		}
		time.Sleep(time.Second * 3)
		tries++
		if tries > 15 {
			return fmt.Errorf("pod %s/%s is not running", namespace, name)
		}
	}
	return nil
}
*/

func getNodeNames(valkey *hyperv1.Valkey) string {
	var nodes []string
	for i := 0; i < int(valkey.Spec.Shards)*(int(valkey.Spec.Replicas)+1); i++ {
		nodes = append(nodes, valkey.Name+"-"+fmt.Sprint(i)+"."+valkey.Name+"-headless")
	}
	return strings.Join(nodes, " ")
}

func (r *ValkeyReconciler) upsertPodDisruptionBudget(ctx context.Context, valkey *hyperv1.Valkey) error {
	logger := log.FromContext(ctx)

	logger.Info("upserting pod disruption budget")
	pdb := &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{
			Name:      valkey.Name,
			Namespace: valkey.Namespace,
			Labels:    labels(valkey),
		},
		Spec: policyv1.PodDisruptionBudgetSpec{
			MaxUnavailable: func(i intstr.IntOrString) *intstr.IntOrString { return &i }(intstr.FromInt32(1)),
			Selector: &metav1.LabelSelector{
				MatchLabels: labels(valkey),
			},
		},
	}
	if err := controllerutil.SetControllerReference(valkey, pdb, r.Scheme); err != nil {
		return err
	}
	err := r.Get(ctx, types.NamespacedName{Namespace: valkey.Namespace, Name: valkey.Name}, pdb)
	if err != nil && apierrors.IsNotFound(err) {
		if err := r.Create(ctx, pdb); err != nil {
			logger.Error(err, "failed to create pod disruption budget")
			return err
		}
		r.Recorder.Event(valkey, "Normal", "Created",
			fmt.Sprintf("PodDisruptionBudget %s/%s is created", valkey.Namespace, valkey.Name))
	} else if err != nil {
		logger.Error(err, "failed to fetch pod disruption budget")
		return err
	} else if err == nil && pdb.Spec.MaxUnavailable.IntVal != int32(1) {
		pdb.Spec.MaxUnavailable = func(i intstr.IntOrString) *intstr.IntOrString { return &i }(intstr.FromInt(1))
		if err := r.Update(ctx, pdb); err != nil {
			logger.Error(err, "failed to update pod disruption budget")
			return err
		}
	}
	return nil
}

func (r *ValkeyReconciler) exporter(valkey *hyperv1.Valkey) corev1.Container {
	image := r.GlobalConfig.SidecarImage
	if valkey.Spec.ExporterImage != "" {
		image = valkey.Spec.ExporterImage
	}

	container := corev1.Container{
		Name:            Metrics,
		Image:           image,
		ImagePullPolicy: "IfNotPresent",
		Ports: []corev1.ContainerPort{
			{
				Name:          "valkey-metrics",
				ContainerPort: 9121,
			},
		},
		Env: []corev1.EnvVar{
			{
				Name:  "VALKEY_ADDR",
				Value: fmt.Sprintf("valkey://127.0.0.1:%d", ValkeyPort),
			},
			{
				Name:  "VALKEY_EXPORTER_WEB_LISTEN_ADDRESS",
				Value: ":9121",
			},
			{
				Name:  "VALKY_ALIAS",
				Value: valkey.Name,
			},
			{
				Name:  "BITNAMI_DEBUG",
				Value: "false",
			},
		},
		Command: []string{
			"/sidecar",
			"daemon",
		},
		Resources: getExporterResourceRequirements(),
		SecurityContext: &corev1.SecurityContext{
			AllowPrivilegeEscalation: func(b bool) *bool { return &b }(false),
			Capabilities: &corev1.Capabilities{
				Drop: []corev1.Capability{
					"ALL",
				},
			},
			Privileged:             func(b bool) *bool { return &b }(false),
			ReadOnlyRootFilesystem: func(b bool) *bool { return &b }(true),
			RunAsNonRoot:           func(b bool) *bool { return &b }(true),
			RunAsUser:              func(i int64) *int64 { return &i }(1001),
			RunAsGroup:             func(i int64) *int64 { return &i }(1001),
			SELinuxOptions:         &corev1.SELinuxOptions{},
			SeccompProfile: &corev1.SeccompProfile{
				Type: "RuntimeDefault",
			},
		},
	}
	if !valkey.Spec.AnonymousAuth {
		container.Env = append(container.Env, corev1.EnvVar{
			Name: "VALKEY_PASSWORD",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					Key: getServicePasswordKey(valkey),
					LocalObjectReference: corev1.LocalObjectReference{
						Name: getServicePasswordName(valkey),
					},
				},
			},
		})
		container.Env = append(container.Env, corev1.EnvVar{
			Name: "REDIS_PASSWORD",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					Key: getServicePasswordKey(valkey),
					LocalObjectReference: corev1.LocalObjectReference{
						Name: getServicePasswordName(valkey),
					},
				},
			},
		})
	}
	if valkey.Spec.TLS {
		container.VolumeMounts = append(container.VolumeMounts, corev1.VolumeMount{
			Name:      "valkey-tls",
			MountPath: "/etc/valkey/certs",
		})

		tlsExporterEnv := []corev1.EnvVar{
			{
				Name:  "REDIS_ADDR",
				Value: fmt.Sprintf("rediss://localhost:%d", ValkeyPort),
			},
			{
				Name:  "REDIS_EXPORTER_SKIP_TLS_VERIFICATION",
				Value: "true",
			},
			/*
				{
					Name:  "REDIS_EXPORTER_TLS_CLIENT_KEY_FILE",
					Value: "/etc/valkey/certs/tls.key",
				},
				{
					Name:  "REDIS_EXPORTER_TLS_CLIENT_CERT_FILE",
					Value: "/etc/valkey/certs/tls.crt",
				}, */
			{
				Name:  "REDIS_EXPORTER_TLS_CA_FILE",
				Value: "/etc/valkey/certs/ca.crt",
			},
		}
		container.Env = append(container.Env, tlsExporterEnv...)
	}
	return container
}

func generatePVC(valkey *hyperv1.Valkey) corev1.PersistentVolumeClaim {
	pv := corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "valkey-data",
			Labels: labels(valkey),
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{
				"ReadWriteOnce",
			},
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{
					"storage": func(s string) resource.Quantity { return resource.MustParse(s) }(DefaultVolumeSize),
				},
			},
		},
	}
	if valkey.Spec.Storage != nil {
		pv = *valkey.Spec.Storage
		pv.ObjectMeta.Name = "valkey-data" //nolint:staticcheck
		if pv.ObjectMeta.Labels == nil {   //nolint:staticcheck
			pv.ObjectMeta.Labels = labels(valkey) //nolint:staticcheck
		} else {
			for k, v := range labels(valkey) {
				pv.ObjectMeta.Labels[k] = v //nolint:staticcheck
			}
		}
		if len(pv.Spec.AccessModes) == 0 {
			pv.Spec.AccessModes = []corev1.PersistentVolumeAccessMode{
				"ReadWriteOnce",
			}
		}
		_, ok := pv.Spec.Resources.Requests["storage"]
		if !ok {
			pv.Spec.Resources.Requests["storage"] = func(s string) resource.Quantity { return resource.MustParse(s) }(DefaultVolumeSize)
		}
	}
	return pv
}

func getResourceRequirements(valkey *hyperv1.Valkey) corev1.ResourceRequirements {
	if valkey.Spec.Resources != nil {
		return *valkey.Spec.Resources
	}

	// Default resource requirements if not specified in the CR
	return corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:              resource.MustParse("100m"),
			corev1.ResourceEphemeralStorage: resource.MustParse("50Mi"),
			corev1.ResourceMemory:           resource.MustParse("128Mi"),
		},
		Limits: corev1.ResourceList{
			corev1.ResourceCPU:              resource.MustParse("150m"),
			corev1.ResourceEphemeralStorage: resource.MustParse("2Gi"),
			corev1.ResourceMemory:           resource.MustParse("192Mi"),
		},
	}
}

func getExporterResourceRequirements() corev1.ResourceRequirements {
	return corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:              resource.MustParse("50m"),
			corev1.ResourceEphemeralStorage: resource.MustParse("50Mi"),
			corev1.ResourceMemory:           resource.MustParse("64Mi"),
		},
		Limits: corev1.ResourceList{
			corev1.ResourceCPU:              resource.MustParse("100m"),
			corev1.ResourceEphemeralStorage: resource.MustParse("2Gi"),
			corev1.ResourceMemory:           resource.MustParse("128Mi"),
		},
	}
}

func getInitContainerResourceRequirements() corev1.ResourceRequirements {
	return corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("50m"),
			corev1.ResourceMemory: resource.MustParse("64Mi"),
		},
		Limits: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("100m"),
			corev1.ResourceMemory: resource.MustParse("128Mi"),
		},
	}
}

func (r *ValkeyReconciler) upsertStatefulSet(ctx context.Context, valkey *hyperv1.Valkey) error { // nolint:gocyclo
	logger := log.FromContext(ctx)

	logger.Info("upserting statefulset")
	tls := "no"
	endpointType := "ip"
	if valkey.Spec.TLS {
		tls = "yes"
		endpointType = "hostname"
	}
	image := r.GlobalConfig.ValkeyImage
	if valkey.Spec.Image != "" {
		image = valkey.Spec.Image
	}
	sts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      valkey.Name,
			Namespace: valkey.Namespace,
			Labels:    labels(valkey),
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas: func(i int32) *int32 { return &i }(valkey.Spec.Shards * (valkey.Spec.Replicas + 1)),
			Selector: &metav1.LabelSelector{
				MatchLabels: labels(valkey),
			},
			ServiceName:         valkey.Name + "-headless",
			PodManagementPolicy: appsv1.ParallelPodManagement,
			VolumeClaimTemplates: []corev1.PersistentVolumeClaim{
				generatePVC(valkey),
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels:      labels(valkey),
					Annotations: annotations(valkey),
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: valkey.Name,
					EnableServiceLinks: func(b bool) *bool { return &b }(false),
					HostNetwork:        false,
					SecurityContext: &corev1.PodSecurityContext{
						FSGroup:             func(i int64) *int64 { return &i }(1001),
						FSGroupChangePolicy: func(s corev1.PodFSGroupChangePolicy) *corev1.PodFSGroupChangePolicy { return &s }(corev1.FSGroupChangeAlways),
						SupplementalGroups:  []int64{},
						Sysctls:             []corev1.Sysctl{},
					},
					AutomountServiceAccountToken: func(b bool) *bool { return &b }(false),
					Affinity: &corev1.Affinity{
						PodAntiAffinity: &corev1.PodAntiAffinity{
							PreferredDuringSchedulingIgnoredDuringExecution: []corev1.WeightedPodAffinityTerm{
								{
									Weight: 1,
									PodAffinityTerm: corev1.PodAffinityTerm{
										LabelSelector: &metav1.LabelSelector{
											MatchLabels: labels(valkey),
										},
										TopologyKey: "kubernetes.io/hostname",
									},
								},
							},
						},
					},
					Tolerations:  valkey.Spec.Tolerations,
					NodeSelector: valkey.Spec.NodeSelector,
					Containers: []corev1.Container{
						{
							Image: image,
							SecurityContext: &corev1.SecurityContext{
								AllowPrivilegeEscalation: func(b bool) *bool { return &b }(false),
								Capabilities: &corev1.Capabilities{
									Drop: []corev1.Capability{
										"ALL",
									},
								},
								Privileged:             func(b bool) *bool { return &b }(false),
								ReadOnlyRootFilesystem: func(b bool) *bool { return &b }(true),
								RunAsNonRoot:           func(b bool) *bool { return &b }(true),
								RunAsUser:              func(i int64) *int64 { return &i }(1001),
								RunAsGroup:             func(i int64) *int64 { return &i }(1001),
								SELinuxOptions:         &corev1.SELinuxOptions{},
								SeccompProfile: &corev1.SeccompProfile{
									Type: "RuntimeDefault",
								},
							},
							Name:            Valkey,
							ImagePullPolicy: "IfNotPresent",
							Command: []string{
								"valkey-server",
								"/valkey/etc/valkey.conf",
								"--protected-mode", "no",
							},
							Env: []corev1.EnvVar{
								{
									Name: "POD_NAME",
									ValueFrom: &corev1.EnvVarSource{
										FieldRef: &corev1.ObjectFieldSelector{
											APIVersion: "v1",
											FieldPath:  "metadata.name",
										},
									},
								},
								{
									Name:  "VALKEY_NODES",
									Value: getNodeNames(valkey),
								},
								{
									Name:  "VALKEY_CLUSTER_PREFERRED_ENDPOINT_TYPE",
									Value: endpointType,
								},
								{
									Name:  "VALKEY_AOF_ENABLED",
									Value: "yes",
								},
								{
									Name:  "VALKEY_TLS_ENABLED",
									Value: tls,
								},
								{
									Name:  "VALKEY_PORT_NUMBER",
									Value: fmt.Sprintf("%d", ValkeyPort),
								},
							},
							Ports: []corev1.ContainerPort{
								{
									Name:          "tcp-valkey",
									ContainerPort: ValkeyPort,
								},
								{
									Name:          "tcp-valkey-bus",
									ContainerPort: 16379,
								},
							},
							LivenessProbe: &corev1.Probe{
								InitialDelaySeconds: 5,
								PeriodSeconds:       5,
								FailureThreshold:    5,
								TimeoutSeconds:      6,
								SuccessThreshold:    1,
								ProbeHandler: corev1.ProbeHandler{
									Exec: &corev1.ExecAction{
										Command: []string{
											"sh",
											"-c",
											"/scripts/ping_liveness_local.sh 5",
										},
									},
								},
							},
							ReadinessProbe: &corev1.Probe{
								InitialDelaySeconds: 5,
								PeriodSeconds:       5,
								FailureThreshold:    5,
								TimeoutSeconds:      2,
								SuccessThreshold:    1,
								ProbeHandler: corev1.ProbeHandler{
									Exec: &corev1.ExecAction{
										Command: []string{
											"sh",
											"-c",
											"/scripts/ping_readiness_local.sh 1",
										},
									},
								},
							},
							Resources: getResourceRequirements(valkey),
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "scripts",
									MountPath: "/scripts",
								},
								{
									Name:      "valkey-data",
									MountPath: "/data",
								},
								{
									Name:      "empty-dir",
									MountPath: "/valkey/etc",
									SubPath:   "app-conf-dir",
								},
								{
									Name:      "valkey-conf",
									MountPath: "/valkey/etc/valkey.conf",
									SubPath:   "valkey.conf",
								},
								{
									Name:      "empty-dir",
									MountPath: "/valkey/tmp",
									SubPath:   "app-tmp-dir",
								},
								{
									Name:      "empty-dir",
									MountPath: "/var/logs/valkey",
									SubPath:   "app-logs-dir",
								},
								{
									Name:      "empty-dir",
									MountPath: "/tmp",
									SubPath:   "tmp-dir",
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "scripts",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: valkey.Name,
									},
									DefaultMode: func(i int32) *int32 { return &i }(0755),
								},
							},
						},
						{
							Name: "valkey-conf",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: valkey.Name,
									},
								},
							},
						},
						{
							Name: "empty-dir",
							VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{},
							},
						},
					},
				},
			},
		},
	}
	if valkey.Spec.VolumePermissions {
		sts.Spec.Template.Spec.InitContainers = []corev1.Container{
			{
				Name:            "volume-permissions",
				Image:           image,
				ImagePullPolicy: "IfNotPresent",
				Command: []string{
					"/bin/chown",
					"-R",
					"1001:1001",
					"/data",
				},
				Resources: getInitContainerResourceRequirements(),
				SecurityContext: &corev1.SecurityContext{
					RunAsUser: func(i int64) *int64 { return &i }(0),
				},
				VolumeMounts: []corev1.VolumeMount{
					{
						Name:      "valkey-data",
						MountPath: "/data",
					},
					{
						Name:      "empty-dir",
						MountPath: "/tmp",
						SubPath:   "tmp-dir",
					},
				},
			},
		}
	}
	if valkey.Spec.TLS {
		tlsEnv := []corev1.EnvVar{
			{
				Name:  "VALKEY_TLS_AUTH_CLIENTS",
				Value: "no",
			},
			{
				Name:  "VALKEY_TLS_PORT_NUMBER",
				Value: fmt.Sprintf("%d", ValkeyPort),
			},
			{
				Name:  "VALKEY_TLS_CERT_FILE",
				Value: "/etc/valkey/certs/tls.crt",
			},
			{
				Name:  "VALKEY_TLS_KEY_FILE",
				Value: "/etc/valkey/certs/tls.key",
			},
			{
				Name:  "VALKEY_TLS_CA_FILE",
				Value: "/etc/valkey/certs/ca.crt",
			},
		}
		sts.Spec.Template.Spec.Containers[0].Env = append(sts.Spec.Template.Spec.Containers[0].Env, tlsEnv...)
		sts.Spec.Template.Spec.Containers[0].VolumeMounts = append(sts.Spec.Template.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{
			Name:      "valkey-tls",
			MountPath: "/etc/valkey/certs",
		})
		sts.Spec.Template.Spec.Volumes = append(sts.Spec.Template.Spec.Volumes, corev1.Volume{
			Name: "valkey-tls",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: valkey.Name + "-tls",
				},
			},
		})
	}
	if !valkey.Spec.AnonymousAuth {
		sts.Spec.Template.Spec.Containers[0].Env = append(sts.Spec.Template.Spec.Containers[0].Env, corev1.EnvVar{
			Name: "REDISCLI_AUTH",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					Key: getServicePasswordKey(valkey),
					LocalObjectReference: corev1.LocalObjectReference{
						Name: getServicePasswordName(valkey),
					},
				},
			},
		})
		sts.Spec.Template.Spec.Containers[0].Env = append(sts.Spec.Template.Spec.Containers[0].Env, corev1.EnvVar{
			Name: "VALKEY_PASSWORD",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					Key: getServicePasswordKey(valkey),
					LocalObjectReference: corev1.LocalObjectReference{
						Name: getServicePasswordName(valkey),
					},
				},
			},
		})
		sts.Spec.Template.Spec.Containers[0].Command = []string{
			"valkey-server",
			"/valkey/etc/valkey.conf",
			"--requirepass", "$(VALKEY_PASSWORD)",
			"--primaryauth", "$(VALKEY_PASSWORD)",
		}
	}
	if valkey.Spec.ExternalAccess != nil && valkey.Spec.ExternalAccess.Enabled {
		sts.Spec.Template.Spec.Containers[0].Env = append(sts.Spec.Template.Spec.Containers[0].Env, corev1.EnvVar{
			Name:  "VALKEY_EXTERNAL_ACCESS",
			Value: "yes",
		})
	}
	if valkey.Spec.Prometheus {
		sts.Spec.Template.Spec.Containers = append(sts.Spec.Template.Spec.Containers, r.exporter(valkey))
	}
	if err := controllerutil.SetControllerReference(valkey, sts, r.Scheme); err != nil {
		return err
	}

	existingSts := &appsv1.StatefulSet{}
	err := r.Get(ctx, types.NamespacedName{Namespace: valkey.Namespace, Name: valkey.Name}, existingSts)
	if err != nil && apierrors.IsNotFound(err) {
		if err := r.Create(ctx, sts); err != nil {
			logger.Error(err, "failed to update statefulset")
			return err
		}
		r.Recorder.Event(valkey, "Normal", "Created",
			fmt.Sprintf("StatefulSet %s/%s is created", valkey.Namespace, valkey.Name))
	} else if err != nil {
		logger.Error(err, "failed fetching statefulset")
		return err
	}

	updateReasons := make([]string, 0)
	if !cmp.Equal(existingSts.Spec.Template.Spec.Containers[0].Env, sts.Spec.Template.Spec.Containers[0].Env) {
		updateReasons = append(updateReasons, "env")
	}
	if !cmp.Equal(existingSts.Spec.Template.Spec.Containers[0].Command, sts.Spec.Template.Spec.Containers[0].Command) {
		updateReasons = append(updateReasons, "command")
	}

	if *existingSts.Spec.Replicas != (valkey.Spec.Shards * (valkey.Spec.Replicas + 1)) {
		replicas := valkey.Spec.Shards * (valkey.Spec.Replicas + 1)
		sts.Spec.Replicas = &replicas
		sts.Spec.Template.Spec.Containers[0].Env[1].Value = getNodeNames(valkey)
		updateReasons = append(updateReasons, "replicas")
	}
	if valkey.Spec.Prometheus && len(existingSts.Spec.Template.Spec.Containers) == 1 {
		sts.Spec.Template.Spec.Containers = append(sts.Spec.Template.Spec.Containers, r.exporter(valkey))
		updateReasons = append(updateReasons, "exporter")
	}
	if existingSts.Spec.Template.Spec.Containers[0].Image != image {
		sts.Spec.Template.Spec.Containers[0].Image = image
		if valkey.Spec.VolumePermissions {
			sts.Spec.Template.Spec.InitContainers[0].Image = image
		}
		updateReasons = append(updateReasons, "image")
	}
	if valkey.Spec.Storage != nil && len(existingSts.Spec.VolumeClaimTemplates) == 0 {
		err = fmt.Errorf("storage has been added but cannot be updated in a statefuleset")
		logger.Error(err, "unable to update storage in statefulset")
		return err
	} else if valkey.Spec.Storage == nil && len(existingSts.Spec.VolumeClaimTemplates) == 1 {
		err = fmt.Errorf("storage has been removed but cannot be updated in a statefuleset")
		logger.Error(err, "unable to update storage in statefulset")
		return err
	} else {
		defaultStorageClass := r.defaultStorageClass(ctx)
		currentPVCSpec := existingSts.Spec.VolumeClaimTemplates[0].Spec
		definedPVCSpec := valkey.Spec.Storage.Spec
		if definedPVCSpec.VolumeMode == nil {
			// The default is Filesystem
			fs := corev1.PersistentVolumeFilesystem
			definedPVCSpec.VolumeMode = &fs
		}
		if definedPVCSpec.StorageClassName == nil {
			definedPVCSpec.StorageClassName = &defaultStorageClass
		}
		if currentPVCSpec.StorageClassName == nil {
			currentPVCSpec.StorageClassName = &defaultStorageClass
		}
		if !cmp.Equal(currentPVCSpec, definedPVCSpec) {
			err = fmt.Errorf("volume claim template has changed and cannot be updated in a statefuleset")
			logger.Error(err, "unable to update storage in statefulset")
			return err
		}
	}
	exporterImage := r.GlobalConfig.SidecarImage
	if valkey.Spec.ExporterImage != "" {
		exporterImage = valkey.Spec.ExporterImage
	}
	if valkey.Spec.Prometheus && existingSts.Spec.Template.Spec.Containers[1].Image != exporterImage {
		sts.Spec.Template.Spec.Containers[1].Image = exporterImage
		if err := r.Update(ctx, sts); err != nil {
			logger.Error(err, "failed to update statefulset exporter image")
			return err
		}
		r.Recorder.Event(valkey, "Normal", "Updated",
			fmt.Sprintf("StatefulSet %s/%s is updated (exporter image)", valkey.Namespace, valkey.Name))
	}

	if len(updateReasons) > 0 {
		if err := r.Update(ctx, sts); err != nil {
			logger.Error(err, "failed to update statefulset")
			return err
		}
		r.Recorder.Event(valkey, "Normal", "Updated",
			fmt.Sprintf("StatefulSet %s/%s is updated (%s)",
				valkey.Namespace, valkey.Name,
				strings.Join(updateReasons, ", "),
			),
		)

	}

	return nil
}

// defaultStorageClass returns the default storage class for the cluster
func (r *ValkeyReconciler) defaultStorageClass(ctx context.Context) string {
	logger := log.FromContext(ctx)

	storageClassList := &storagev1.StorageClassList{}
	if err := r.List(ctx, storageClassList); err != nil {
		logger.Error(err, "failed to list storage classes")
		return ""
	}
	for _, sc := range storageClassList.Items {
		if sc.Annotations["storageclass.kubernetes.io/is-default-class"] == "true" {
			return sc.Name
		}
	}
	return ""
}

// SetupWithManager sets up the controller with the Manager.
func (r *ValkeyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&hyperv1.Valkey{}).
		Complete(r)
}

// logClusterDetails logs the details of the cluster node configuration
func logClusterDetails(ctx context.Context, vClient valkeyClient.Client) error {
	logger := log.FromContext(ctx)

	nodes, err := vClient.Do(ctx, vClient.B().ClusterNodes().Build()).ToString()
	if err != nil {
		return err
	}

	for _, node := range strings.Split(nodes, "\n") {
		if node == "" {
			continue
		}
		parts := strings.Split(node, " ")
		if len(parts) < 8 {
			logger.Info("skipping invalid node entry", "entry", node)
			continue
		}

		nodeID := strings.Replace(parts[0], "txt:", "", 1)
		address := parts[1]
		role := parts[2]
		flags := parts[3]
		slotRange := parts[8:]

		logger.Info("cluster node details",
			"nodeID", nodeID,
			"address", address,
			"role", role,
			"flags", flags,
			"slotRange", slotRange,
		)
	}
	return nil
}
