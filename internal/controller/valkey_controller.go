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
	"embed"
	"fmt"
	"io"
	"math/big"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	hyperv1 "hyperspike.io/valkey-operator/api/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	Scheme *runtime.Scheme
}

//go:embed scripts/*
var scripts embed.FS

// +kubebuilder:rbac:groups=hyperspike.io,resources=valkeys,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=hyperspike.io,resources=valkeys/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=hyperspike.io,resources=valkeys/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="apps",resources=statefulsets,verbs=get;list;watch;create;update;patch;delete

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
	if err := r.upsertSecret(ctx, valkey); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.upsertStatefulSet(ctx, valkey); err != nil {
		return ctrl.Result{}, err
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
	if err := r.Create(ctx, svc); err != nil {
		if errors.IsAlreadyExists(err) {
			if err := r.Update(ctx, svc); err != nil {
				return err
			}
		} else {
			return err
		}
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
	if err := r.Create(ctx, cm); err != nil {
		if errors.IsAlreadyExists(err) {
			if err := r.Update(ctx, cm); err != nil {
				logger.Error(err, "failed to update service", "valkey", valkey.Name, "namespace", valkey.Namespace)
				return err
			}
		} else {
			logger.Error(err, "failed to create service", "valkey", valkey.Name, "namespace", valkey.Namespace)
			return err
		}
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
	}
	return nil
}

func (r *ValkeyReconciler) upsertSecret(ctx context.Context, valkey *hyperv1.Valkey) error {
	logger := log.FromContext(ctx)

	logger.Info("upserting secret", "valkey", valkey.Name, "namespace", valkey.Namespace)
	rs, err := randString(16)
	if err != nil {
		return err
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
	if err := r.Create(ctx, secret); err != nil {
		if errors.IsAlreadyExists(err) {
			if err := r.Update(ctx, secret); err != nil {
				logger.Error(err, "failed to update secret", "valkey", valkey.Name, "namespace", valkey.Namespace)
				return err
			}
		} else {
			logger.Error(err, "failed to create secret", "valkey", valkey.Name, "namespace", valkey.Namespace)
			return err
		}
	}
	return nil
}

func (r *ValkeyReconciler) upsertServiceAccount(ctx context.Context, valkey *hyperv1.Valkey) error {
	logger := log.FromContext(ctx)

	logger.Info("upserting service account", "valkey", valkey.Name, "namespace", valkey.Namespace)
	svc := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      valkey.Name,
			Namespace: valkey.Namespace,
			Labels:    labels(valkey),
		},
	}
	if err := r.Create(ctx, svc); err != nil {
		if errors.IsAlreadyExists(err) {
			if err := r.Update(ctx, svc); err != nil {
				logger.Error(err, "failed to update service account", "valkey", valkey.Name, "namespace", valkey.Namespace)
				return err
			}
		} else {
			logger.Error(err, "failed to create service account", "valkey", valkey.Name, "namespace", valkey.Namespace)
			return err
		}
	}
	return nil
}

func (r *ValkeyReconciler) upsertStatefulSet(ctx context.Context, valkey *hyperv1.Valkey) error {
	logger := log.FromContext(ctx)

	logger.Info("upserting statefulset", "valkey", valkey.Name, "namespace", valkey.Namespace)
	sts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      valkey.Name,
			Namespace: valkey.Namespace,
			Labels:    labels(valkey),
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas: func(i int32) *int32 { return &i }(3),
			Selector: &metav1.LabelSelector{
				MatchLabels: labels(valkey),
			},
			ServiceName:         valkey.Name + "-headless",
			PodManagementPolicy: appsv1.ParallelPodManagement,
			VolumeClaimTemplates: []corev1.PersistentVolumeClaim{
				{
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
				},
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
					Containers: []corev1.Container{
						{
							Image: "docker.io/bitnami/valkey-cluster:7.2.5-debian-12-r4",
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
								`# Backwards compatibility change
if ! [[ -f /opt/bitnami/valkey/etc/valkey.conf ]]; then
  echo COPYING FILE
  cp  /opt/bitnami/valkey/etc/valkey-default.conf /opt/bitnami/valkey/etc/valkey.conf
fi
pod_index=($(echo "$POD_NAME" | tr "-" "\n"))
pod_index="${pod_index[-1]}"
if [[ "$pod_index" == "0" ]]; then
  export VALKEY_CLUSTER_CREATOR="yes"
  export VALKEY_CLUSTER_REPLICAS="0"
fi
/opt/bitnami/scripts/valkey-cluster/entrypoint.sh /opt/bitnami/scripts/valkey-cluster/run.sh`,
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
									Name: "VALKEY_NODES",
									// @TODO generate nodes function
									Value: valkey.Name + "-0." + valkey.Name + "-headless." + valkey.Namespace + ".svc " + valkey.Name + "-1." + valkey.Name + "-headless." + valkey.Namespace + ".svc " + valkey.Name + "-2." + valkey.Name + "-headless." + valkey.Namespace + ".svc",
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
									Name:  "VALKEY_AOF_ENABLED",
									Value: "yes",
								},
								{
									Name:  "VALKEY_TLS_ENABLED",
									Value: "no",
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
	if err := r.Create(ctx, sts); err != nil {
		if errors.IsAlreadyExists(err) {
			if err := r.Update(ctx, sts); err != nil {
				logger.Error(err, "failed to update statefulset", "valkey", valkey.Name, "namespace", valkey.Namespace)
				return err
			}
		} else {
			logger.Error(err, "failed to create statefulset", "valkey", valkey.Name, "namespace", valkey.Namespace)
			return err
		}
	}
	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ValkeyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&hyperv1.Valkey{}).
		Complete(r)
}
