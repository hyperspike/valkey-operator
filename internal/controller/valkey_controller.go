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
	"strings"
	"time"

	valkeyClient "github.com/valkey-io/valkey-go"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	certv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmetav1 "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	hyperv1 "hyperspike.io/valkey-operator/api/v1"
	globalcfg "hyperspike.io/valkey-operator/cfg"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	Metrics = "metrics"
)

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
// +kubebuilder:rbac:groups="apps",resources=statefulsets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=policy,resources=poddisruptionbudgets,verbs=get;list;watch;create;update;patch;delete
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
func (r *ValkeyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	_ = log.FromContext(ctx)

	valkey := &hyperv1.Valkey{}
	if err := r.Get(ctx, req.NamespacedName, valkey); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if err := r.upsertConfigMap(ctx, valkey); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.upsertService(ctx, valkey); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.upsertServiceHeadless(ctx, valkey); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.upsertServiceAccount(ctx, valkey); err != nil {
		return ctrl.Result{}, err
	}
	if valkey.Spec.Prometheus {
		if err := r.upsertServiceMonitor(ctx, valkey); err != nil {
			return ctrl.Result{}, err
		}
		if err := r.upsertMetricsService(ctx, valkey); err != nil {
			return ctrl.Result{}, err
		}
	}

	if valkey.Spec.TLS {
		if err := r.upsertCertificate(ctx, valkey); err != nil {
			return ctrl.Result{}, err
		}
	}

	password, err := r.upsertSecret(ctx, valkey, true)
	if err != nil {
		return ctrl.Result{}, err
	}
	if err := r.upsertPodDisruptionBudget(ctx, valkey); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.upsertStatefulSet(ctx, valkey); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.checkState(ctx, valkey, password); err != nil {
		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 3}, nil
	}
	if err := r.balanceNodes(ctx, valkey); err != nil {
		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 5}, nil
	}

	return ctrl.Result{}, nil
}

func labels(valkey *hyperv1.Valkey) map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":      "valkey",
		"app.kubernetes.io/instance":  valkey.Name,
		"app.kubernetes.io/component": "valkey",
	}
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

func (r *ValkeyReconciler) checkState(ctx context.Context, valkey *hyperv1.Valkey, password string) error {
	logger := log.FromContext(ctx)

	opt := valkeyClient.ClientOption{
		InitAddress: []string{valkey.Name + "." + valkey.Namespace + ".svc:6379"},
		Password:    password,
	}
	if valkey.Spec.TLS {
		ca, err := r.getCACertificate(ctx, valkey)
		if err != nil {
			logger.Error(err, "failed to get ca certificate")
			return err
		}
		if ca == "" {
			return fmt.Errorf("ca certificate not ready")
		}
		certpool, err := x509.SystemCertPool()
		if err != nil {
			logger.Error(err, "failed to get system cert pool")
			return err
		}
		certpool.AppendCertsFromPEM([]byte(ca))
		opt.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    certpool,
			ServerName: valkey.Name + "." + valkey.Namespace + ".svc",
		}
	}
	vClient, err := valkeyClient.NewClient(opt)
	if err != nil {
		logger.Error(err, "failed to create valkey client", "valkey", valkey.Name, "namespace", valkey.Namespace)
		return err
	}
	defer vClient.Close()
	if err := vClient.Do(ctx, vClient.B().Ping().Build()).Error(); err != nil {
		logger.Error(err, "failed to ping valkey", "valkey", valkey.Name, "namespace", valkey.Namespace)
		return err
	}
	valkey.Status.Ready = true
	if err := r.Client.Status().Update(ctx, valkey); err != nil {
		logger.Error(err, "Valkey status update failed.", "valkey", valkey.Name, "namespace", valkey.Namespace)
		return err
	}
	return nil
}

func (r *ValkeyReconciler) upsertService(ctx context.Context, valkey *hyperv1.Valkey) error {
	logger := log.FromContext(ctx)

	logger.Info("upserting service", "valkey", valkey.Name, "namespace", valkey.Namespace)

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
					Port:       6379,
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
		if errors.IsAlreadyExists(err) {
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

	logger.Info("upserting configmap", "valkey", valkey.Name, "namespace", valkey.Namespace)

	defaultConf, err := scripts.ReadFile("scripts/default.conf")
	if err != nil {
		logger.Error(err, "failed to read default.conf")
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
			"valkey-default.conf":     string(defaultConf),
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
		if errors.IsAlreadyExists(err) {
			if err := r.Update(ctx, cm); err != nil {
				logger.Error(err, "failed to update ConfigMap", "valkey", valkey.Name, "namespace", valkey.Namespace)
				return err
			}
		} else {
			logger.Error(err, "failed to create ConfigMap", "valkey", valkey.Name, "namespace", valkey.Namespace)
			return err
		}
	} else {
		r.Recorder.Event(valkey, "Normal", "Created",
			fmt.Sprintf("ConfigMap %s/%s is created", valkey.Namespace, valkey.Name))
	}
	return nil
}
func (r *ValkeyReconciler) upsertServiceHeadless(ctx context.Context, valkey *hyperv1.Valkey) error {
	logger := log.FromContext(ctx)

	logger.Info("upserting service", "valkey", valkey.Name, "namespace", valkey.Namespace)

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
					Port:       6379,
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
		if errors.IsAlreadyExists(err) {
			if err := r.Update(ctx, svc); err != nil {
				logger.Error(err, "failed to update service", "valkey", valkey.Name, "namespace", valkey.Namespace)
				return err
			}
		} else {
			logger.Error(err, "failed to create service", "valkey", valkey.Name, "namespace", valkey.Namespace)
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

	logger.Info("upserting metrics service", "valkey", valkey.Name, "namespace", valkey.Namespace)

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
		if errors.IsAlreadyExists(err) {
			if err := r.Update(ctx, svc); err != nil {
				logger.Error(err, "failed to update metrics service", "valkey", valkey.Name, "namespace", valkey.Namespace)
				return err
			}
		} else {
			logger.Error(err, "failed to create metrics service", "valkey", valkey.Name, "namespace", valkey.Namespace)
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

	logger.Info("upserting prometheus service monitor", "valkey", valkey.Name, "namespace", valkey.Namespace)

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
	if err != nil && errors.IsNotFound(err) {
		if err := r.Create(ctx, sm); err != nil {
			logger.Error(err, "failed to create prometheus service monitor", "valkey", valkey.Name, "namespace", valkey.Namespace)
			return err
		}
		r.Recorder.Event(valkey, "Normal", "Created",
			fmt.Sprintf("ServiceMonitor %s/%s is created", valkey.Namespace, valkey.Name))
	} else if err != nil {
		logger.Error(err, "failed to fetch prometheus service monitor", "valkey", valkey.Name, "namespace", valkey.Namespace)
		return err
	} else if err == nil && false { // detect changes
		// updates here
		if err := r.Update(ctx, sm); err != nil {
			logger.Error(err, "failed to update prometheus service monitor", "valkey", valkey.Name, "namespace", valkey.Namespace)
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
	if err != nil && errors.IsNotFound(err) {
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

func (r *ValkeyReconciler) upsertSecret(ctx context.Context, valkey *hyperv1.Valkey, once bool) (string, error) {
	logger := log.FromContext(ctx)

	logger.Info("upserting secret", "valkey", valkey.Name, "namespace", valkey.Namespace)
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
	if err != nil && errors.IsNotFound(err) {
		if err := r.Create(ctx, secret); err != nil {
			logger.Error(err, "failed to update secret", "valkey", valkey.Name, "namespace", valkey.Namespace)
			return "", err
		}
		r.Recorder.Event(valkey, "Normal", "Created",
			fmt.Sprintf("Secret %s/%s is created", valkey.Namespace, valkey.Name))
	} else if err == nil && !once {
		if err := r.Update(ctx, secret); err != nil {
			logger.Error(err, "failed to create secret", "valkey", valkey.Name, "namespace", valkey.Namespace)
			return "", err
		}
	} else if err != nil {
		logger.Error(err, "failed fetching secret", "valkey", valkey.Name, "namespace", valkey.Namespace)
		return "", err
	}
	return string(secret.Data["password"]), nil
}

func (r *ValkeyReconciler) upsertServiceAccount(ctx context.Context, valkey *hyperv1.Valkey) error {
	logger := log.FromContext(ctx)

	logger.Info("upserting service account", "valkey", valkey.Name, "namespace", valkey.Namespace)
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
			if err := r.Update(ctx, sa); err != nil {
				logger.Error(err, "failed to update service account", "valkey", valkey.Name, "namespace", valkey.Namespace)
				return err
			}
		} else {
			logger.Error(err, "failed to create service account", "valkey", valkey.Name, "namespace", valkey.Namespace)
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

func (r *ValkeyReconciler) balanceNodes(ctx context.Context, valkey *hyperv1.Valkey) error { // nolint: gocyclo
	logger := log.FromContext(ctx)

	password, err := r.upsertSecret(ctx, valkey, true)
	if err != nil {
		return err
	}

	// connect to the first node!
	opt := valkeyClient.ClientOption{
		InitAddress: []string{valkey.Name + "-0." + valkey.Name + "-headless." + valkey.Namespace + ".svc:6379"},
		Password:    password,
	}
	if valkey.Spec.TLS {
		ca, err := r.getCACertificate(ctx, valkey)
		if err != nil {
			logger.Error(err, "failed to get ca certificate")
			return err
		}
		if ca == "" {
			return fmt.Errorf("ca certificate not ready")
		}
		certpool, err := x509.SystemCertPool()
		if err != nil {
			logger.Error(err, "failed to get system cert pool")
			return err
		}
		certpool.AppendCertsFromPEM([]byte(ca))
		opt.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    certpool,
		}
	}
	vClient, err := valkeyClient.NewClient(opt)
	if err != nil {
		logger.Error(err, "failed to create valkey client", "valkey", valkey.Name, "namespace", valkey.Namespace)
		return err
	}
	defer vClient.Close()
	if err := vClient.Do(ctx, vClient.B().Ping().Build()).Error(); err != nil {
		logger.Error(err, "failed to ping valkey", "valkey", valkey.Name, "namespace", valkey.Namespace)
		return err
	}

	logger.Info("balancing nodes", "valkey", valkey.Name, "namespace", valkey.Namespace)
	nodes, err := vClient.Do(ctx, vClient.B().ClusterNodes().Build()).ToString()
	if err != nil {
		logger.Error(err, "failed to get nodes", "valkey", valkey.Name, "namespace", valkey.Namespace)
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
	for {
		if len(pods) != int(valkey.Spec.Nodes) {
			pods, err = r.getPodIps(ctx, valkey)
			if err != nil {
				logger.Error(err, "failed to get pod ips", "valkey", valkey.Name, "namespace", valkey.Namespace)
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
				network, err := net.Dial("tcp", ipPod+":6379")
				if err != nil {
					if err := network.Close(); err != nil {
						logger.Error(err, "failed to close network", "valkey", valkey.Name, "namespace", valkey.Namespace)
					}
					time.Sleep(time.Second * 2)
					dial++
					if dial > 60 {
						logger.Error(err, "failed to dial", "valkey", valkey.Name, "namespace", valkey.Namespace)
						break
					}
					continue
				}
				if network != nil {
					if err := network.Close(); err != nil {
						logger.Error(err, "failed to close network", "valkey", valkey.Name, "namespace", valkey.Namespace)
					}
				} else {
					time.Sleep(time.Second * 2)
					dial++
					if dial > 60 {
						logger.Error(err, "failed to dial", "valkey", valkey.Name, "namespace", valkey.Namespace)
						break
					}
					continue
				}
				break
			}
			if dial > 60 {
				logger.Error(err, "failed to dial", "valkey", valkey.Name, "namespace", valkey.Namespace)
				continue
			}
			res, err := vClient.Do(ctx, vClient.B().ClusterMeet().Ip(ipPod).Port(6379).Build()).ToString()
			logger.Info("meeting node "+res, "valkey", valkey.Name, "namespace", valkey.Namespace, "node", pod)
			if err != nil {
				logger.Error(err, "failed to meet node", "valkey", valkey.Name, "namespace", valkey.Namespace, "node", pod)
				return err
			}
			r.Recorder.Event(valkey, "Normal", "Updated", fmt.Sprintf("Node %s added to %s/%s", pod, valkey.Namespace, valkey.Name))
		}
	}

	return nil
}

func (r *ValkeyReconciler) getPodIps(ctx context.Context, valkey *hyperv1.Valkey) (map[string]string, error) {
	logger := log.FromContext(ctx)

	pods := &corev1.PodList{}
	if err := r.List(ctx, pods, client.InNamespace(valkey.Namespace), client.MatchingLabels(labels(valkey))); err != nil {
		logger.Error(err, "failed to list pods", "valkey", valkey.Name, "namespace", valkey.Namespace)
		return nil, err
	}
	ret := map[string]string{}
	for _, pod := range pods.Items {
		ret[pod.Status.PodIP] = pod.Name
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
	for i := 0; i < int(valkey.Spec.Nodes)*(int(valkey.Spec.Replicas)+1); i++ {
		nodes = append(nodes, valkey.Name+"-"+fmt.Sprint(i)+"."+valkey.Name+"-headless")
	}
	return strings.Join(nodes, " ")
}

func (r *ValkeyReconciler) upsertPodDisruptionBudget(ctx context.Context, valkey *hyperv1.Valkey) error {
	logger := log.FromContext(ctx)

	logger.Info("upserting pod disruption budget", "valkey", valkey.Name, "namespace", valkey.Namespace)
	pdb := &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{
			Name:      valkey.Name,
			Namespace: valkey.Namespace,
			Labels:    labels(valkey),
		},
		Spec: policyv1.PodDisruptionBudgetSpec{
			MaxUnavailable: func(i intstr.IntOrString) *intstr.IntOrString { return &i }(intstr.FromInt(1)),
			Selector: &metav1.LabelSelector{
				MatchLabels: labels(valkey),
			},
		},
	}
	if err := controllerutil.SetControllerReference(valkey, pdb, r.Scheme); err != nil {
		return err
	}
	err := r.Get(ctx, types.NamespacedName{Namespace: valkey.Namespace, Name: valkey.Name}, pdb)
	if err != nil && errors.IsNotFound(err) {
		if err := r.Create(ctx, pdb); err != nil {
			logger.Error(err, "failed to create pod disruption budget", "valkey", valkey.Name, "namespace", valkey.Namespace)
			return err
		}
		r.Recorder.Event(valkey, "Normal", "Created",
			fmt.Sprintf("PodDisruptionBudget %s/%s is created", valkey.Namespace, valkey.Name))
	} else if err != nil {
		logger.Error(err, "failed to fetch pod disruption budget", "valkey", valkey.Name, "namespace", valkey.Namespace)
		return err
	} else if err == nil && pdb.Spec.MaxUnavailable.IntVal != int32(1) {
		pdb.Spec.MaxUnavailable = func(i intstr.IntOrString) *intstr.IntOrString { return &i }(intstr.FromInt(1))
		if err := r.Update(ctx, pdb); err != nil {
			logger.Error(err, "failed to update pod disruption budget", "valkey", valkey.Name, "namespace", valkey.Namespace)
			return err
		}
	}
	return nil
}

func (r *ValkeyReconciler) exporter(valkey *hyperv1.Valkey) corev1.Container {
	image := r.GlobalConfig.ExporterImage
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
				Value: "valkey://127.0.0.1:6379",
			},
			{
				Name: "VALKEY_PASSWORD",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						Key: "password",
						LocalObjectReference: corev1.LocalObjectReference{
							Name: valkey.Name,
						},
					},
				},
			},
			{
				Name: "REDIS_PASSWORD",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						Key: "password",
						LocalObjectReference: corev1.LocalObjectReference{
							Name: valkey.Name,
						},
					},
				},
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
			"/bin/bash",
			"-c",
			"redis_exporter", // this seems liable to change
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
	if valkey.Spec.TLS {
		container.VolumeMounts = append(container.VolumeMounts, corev1.VolumeMount{
			Name:      "valkey-tls",
			MountPath: "/etc/valkey/certs",
		})

		tlsExporterEnv := []corev1.EnvVar{
			{
				Name:  "REDIS_ADDR",
				Value: "rediss://localhost:6379",
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
				},
				{
					Name:  "REDIS_EXPORTER_TLS_CA_FILE",
					Value: "/etc/valkey/certs/ca.crt",
				},*/
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
					"storage": func(s string) resource.Quantity { return resource.MustParse(s) }("8Gi"),
				},
			},
		},
	}
	if valkey.Spec.Storage != nil {
		pv = *valkey.Spec.Storage
		pv.ObjectMeta.Name = "valkey-data"
		for k, v := range labels(valkey) {
			pv.ObjectMeta.Labels[k] = v
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
func createCluster(valkey *hyperv1.Valkey) string {
	create := "no"
	if valkey.Spec.Nodes > 1 {
		create = "yes"
	}
	return create
}
func (r *ValkeyReconciler) upsertStatefulSet(ctx context.Context, valkey *hyperv1.Valkey) error {
	logger := log.FromContext(ctx)

	logger.Info("upserting statefulset", "valkey", valkey.Name, "namespace", valkey.Namespace)
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
			Replicas: func(i int32) *int32 { return &i }(valkey.Spec.Nodes * (valkey.Spec.Replicas + 1)),
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
					Labels: labels(valkey),
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
							Name:            "valkey",
							ImagePullPolicy: "IfNotPresent",
							Command: []string{
								"/bin/bash",
								"-c",
							},
							Args: []string{
								fmt.Sprintf(`# Backwards compatibility change
if ! [[ -f /opt/bitnami/valkey/etc/valkey.conf ]]; then
  echo COPYING FILE
  cp  /opt/bitnami/valkey/etc/valkey-default.conf /opt/bitnami/valkey/etc/valkey.conf
fi
pod_index=($(echo "$POD_NAME" | tr "-" "\n"))
pod_index="${pod_index[-1]}"
if [[ "$pod_index" == "0" ]]; then
  export VALKEY_CLUSTER_CREATOR="%s"
  export VALKEY_CLUSTER_REPLICAS="%d"
fi
export VALKEY_CLUSTER_ANNOUNCE_HOSTNAME="${POD_NAME}.%s"
/opt/bitnami/scripts/valkey-cluster/entrypoint.sh /opt/bitnami/scripts/valkey-cluster/run.sh`, createCluster(valkey), valkey.Spec.Replicas, valkey.Name+"-headless."+valkey.Namespace+".svc."+valkey.Spec.ClusterDomain),
							},
							Env: []corev1.EnvVar{
								{
									Name: "POD_NAME",
									ValueFrom: &corev1.EnvVarSource{
										FieldRef: &corev1.ObjectFieldSelector{
											FieldPath: "metadata.name",
										},
									},
								},
								{
									Name:  "VALKEY_NODES",
									Value: getNodeNames(valkey),
								},
								{
									Name: "REDISCLI_AUTH",
									ValueFrom: &corev1.EnvVarSource{
										SecretKeyRef: &corev1.SecretKeySelector{
											Key: "password",
											LocalObjectReference: corev1.LocalObjectReference{
												Name: valkey.Name,
											},
										},
									},
								},
								{
									Name: "VALKEY_PASSWORD",
									ValueFrom: &corev1.EnvVarSource{
										SecretKeyRef: &corev1.SecretKeySelector{
											Key: "password",
											LocalObjectReference: corev1.LocalObjectReference{
												Name: valkey.Name,
											},
										},
									},
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
									Value: "6379",
								},
							},
							Ports: []corev1.ContainerPort{
								{
									Name:          "tcp-valkey",
									ContainerPort: 6379,
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
									MountPath: "/bitnami/valkey/data",
								},
								{
									Name:      "valkey-conf",
									MountPath: "/opt/bitnami/valkey/etc/valkey-default.conf",
									SubPath:   "valkey-default.conf",
								},
								{
									Name:      "empty-dir",
									MountPath: "/opt/bitnami/valkey/etc/",
									SubPath:   "app-conf-dir",
								},
								{
									Name:      "empty-dir",
									MountPath: "/opt/bitnami/valkey/tmp",
									SubPath:   "app-tmp-dir",
								},
								{
									Name:      "empty-dir",
									MountPath: "/opt/bitnami/valkey/logs",
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
					"/bitnami/valkey/data",
				},
				Resources: getInitContainerResourceRequirements(),
				SecurityContext: &corev1.SecurityContext{
					RunAsUser: func(i int64) *int64 { return &i }(0),
				},
				VolumeMounts: []corev1.VolumeMount{
					{
						Name:      "valkey-data",
						MountPath: "/bitnami/valkey/data",
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
				Value: "6379",
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
	if valkey.Spec.Prometheus {
		sts.Spec.Template.Spec.Containers = append(sts.Spec.Template.Spec.Containers, r.exporter(valkey))
	}
	if err := controllerutil.SetControllerReference(valkey, sts, r.Scheme); err != nil {
		return err
	}

	err := r.Get(ctx, types.NamespacedName{Namespace: valkey.Namespace, Name: valkey.Name}, sts)
	if err != nil && errors.IsNotFound(err) {
		if err := r.Create(ctx, sts); err != nil {
			logger.Error(err, "failed to update statefulset", "valkey", valkey.Name, "namespace", valkey.Namespace)
			return err
		}
		r.Recorder.Event(valkey, "Normal", "Created",
			fmt.Sprintf("StatefulSet %s/%s is created", valkey.Namespace, valkey.Name))
	} else if err != nil {
		logger.Error(err, "failed fetching statefulset", "valkey", valkey.Name, "namespace", valkey.Namespace)
		return err
	}

	if *sts.Spec.Replicas != valkey.Spec.Nodes {
		sts.Spec.Replicas = &valkey.Spec.Nodes * (&valkey.Spec.Replicas + 1)
		sts.Spec.Template.Spec.Containers[0].Env[1].Value = getNodeNames(valkey)
		if err := r.Update(ctx, sts); err != nil {
			logger.Error(err, "failed to update statefulset", "valkey", valkey.Name, "namespace", valkey.Namespace)
			return err
		}
		r.Recorder.Event(valkey, "Normal", "Updated", fmt.Sprintf("StatefulSet %s/%s is updated (replicas)", valkey.Namespace, valkey.Name))
	}
	if valkey.Spec.Prometheus && len(sts.Spec.Template.Spec.Containers) == 1 {
		sts.Spec.Template.Spec.Containers = append(sts.Spec.Template.Spec.Containers, r.exporter(valkey))
		if err := r.Update(ctx, sts); err != nil {
			logger.Error(err, "failed to update statefulset", "valkey", valkey.Name, "namespace", valkey.Namespace)
			return err
		}
		r.Recorder.Event(valkey, "Normal", "Updated", fmt.Sprintf("StatefulSet %s/%s is updated (exporter)", valkey.Namespace, valkey.Name))
	}
	if sts.Spec.Template.Spec.Containers[0].Image != image {
		sts.Spec.Template.Spec.Containers[0].Image = image
		if valkey.Spec.VolumePermissions {
			sts.Spec.Template.Spec.InitContainers[0].Image = image
		}
		if err := r.Update(ctx, sts); err != nil {
			logger.Error(err, "failed to update statefulset image", "valkey", valkey.Name, "namespace", valkey.Namespace)
			return err
		}
		r.Recorder.Event(valkey, "Normal", "Updated", fmt.Sprintf("StatefulSet %s/%s is updated (image)", valkey.Namespace, valkey.Name))
	}
	exporterImage := r.GlobalConfig.ExporterImage
	if valkey.Spec.ExporterImage != "" {
		exporterImage = valkey.Spec.ExporterImage
	}
	if valkey.Spec.Prometheus && sts.Spec.Template.Spec.Containers[1].Image != exporterImage {
		sts.Spec.Template.Spec.Containers[1].Image = exporterImage
		if err := r.Update(ctx, sts); err != nil {
			logger.Error(err, "failed to update statefulset exporter image", "valkey", valkey.Name, "namespace", valkey.Namespace)
			return err
		}
		r.Recorder.Event(valkey, "Normal", "Updated", fmt.Sprintf("StatefulSet %s/%s is updated (exporter image)", valkey.Namespace, valkey.Name))
	}

	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ValkeyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&hyperv1.Valkey{}).
		Complete(r)
}
