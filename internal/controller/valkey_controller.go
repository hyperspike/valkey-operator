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
	"embed"

	"k8s.io/apimachinery/pkg/api/errors"
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

	defaultConf, err := scripts.ReadFile("../scripts/default.conf")
	if err != nil {
		logger.Error(err, "failed to read default.conf")
		return err
	}
	pingReadinessLocal, err := scripts.ReadFile("../scripts/ping_readiness_local.sh")
	if err != nil {
		logger.Error(err, "failed to read ping_readiness_local.sh")
		return err
	}
	pingLivenessLocal, err := scripts.ReadFile("../scripts/ping_liveness_local.sh")
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
			"default.conf":            string(defaultConf),
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
			Type:      corev1.ServiceTypeClusterIP,
			ClusterIP: "None",
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

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      valkey.Name,
			Namespace: valkey.Namespace,
			Labels:    labels(valkey),
		},
		Data: map[string][]byte{
			// @TODO generate cluster password
			"": {},
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
			Replicas: nil,
			Selector: nil,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels(valkey),
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{},
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
