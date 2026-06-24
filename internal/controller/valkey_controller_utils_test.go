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
	"strings"
	"testing"
	"text/template"

	hyperspikeiov1 "hyperspike.io/valkey-operator/api/v1"
	globalcfg "hyperspike.io/valkey-operator/cfg"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestLabels(t *testing.T) {
	testLabels := map[string]string{
		"app": "valkey",
	}
	valkey := &hyperspikeiov1.Valkey{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-resource",
			Namespace: "default",
			Labels:    testLabels,
		},
	}
	result := labels(valkey)
	if testLabels["app"] != result["app"] {
		t.Errorf("Expected %v, got %v", testLabels["app"], result["app"])
	}
	if result["app.kubernetes.io/name"] != "valkey" {
		t.Errorf("Expected %v, got %v", "valkey", result["app.kubernetes.io/name"])
	}
	if result["app.kubernetes.io/instance"] != "test-resource" {
		t.Errorf("Expected %v, got %v", "test-resource", result["app.kubernetes.io/instance"])
	}
	result["app.kubernetes.io/component"] = Metrics
	result2 := labels(valkey)
	if result["app.kubernetes.io/component"] != "metrics" {
		t.Errorf("Expected %v, got %v", "metrics", result["app.kubernetes.io/component"])
	}
	if result2["app.kubernetes.io/component"] != "valkey" {
		t.Errorf("Expected %v, got %v", "valkey", result["app.kubernetes.io/component"])
	}
}

func TestAnnotations(t *testing.T) {
	testAnnotations := map[string]string{
		"app": "valkey",
	}
	valkey := &hyperspikeiov1.Valkey{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "test-resource",
			Namespace:   "default",
			Annotations: testAnnotations,
		},
	}
	result := annotations(valkey)
	if testAnnotations["app"] != result["app"] {
		t.Errorf("Expected %v, got %v", testAnnotations["app"], result["app"])
	}
}

func TestServicePasswordKey(t *testing.T) {
	valkey := &hyperspikeiov1.Valkey{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-resource",
			Namespace: "default",
		},
	}
	result := getServicePasswordKey(valkey)
	if result != "password" {
		t.Errorf("Expected %v, got %v", "test-resource", result)
	}
	valkey.Spec.ServicePassword = &corev1.SecretKeySelector{
		Key: "test-password",
	}
	result = getServicePasswordKey(valkey)
	if result != "test-password" {
		t.Errorf("Expected %v, got %v", "test-password", result)
	}
}

func TestServicePasswordName(t *testing.T) {
	valkey := &hyperspikeiov1.Valkey{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-resource",
			Namespace: "default",
		},
	}
	result := getServicePasswordName(valkey)
	if result != "test-resource" {
		t.Errorf("Expected %v, got %v", "test-resource", result)
	}
	valkey.Spec.ServicePassword = &corev1.SecretKeySelector{
		LocalObjectReference: corev1.LocalObjectReference{
			Name: "test-password",
		},
	}
	result = getServicePasswordName(valkey)
	if result != "test-password" {
		t.Errorf("Expected %v, got %v", "test-password", result)
	}
}

func TestStandaloneConfigRender(t *testing.T) {
	render := func(standalone bool) string {
		raw, err := scripts.ReadFile("scripts/valkey.conf")
		if err != nil {
			t.Fatalf("failed to read valkey.conf: %v", err)
		}
		tmpl, err := template.New("valkey.conf").Parse(string(raw))
		if err != nil {
			t.Fatalf("failed to parse valkey.conf: %v", err)
		}
		valkey := &hyperspikeiov1.Valkey{
			Spec: hyperspikeiov1.ValkeySpec{
				Standalone:                   standalone,
				ClusterPreferredEndpointType: "ip",
			},
		}
		buf := &bytes.Buffer{}
		if err := tmpl.Execute(buf, valkey); err != nil {
			t.Fatalf("failed to render valkey.conf: %v", err)
		}
		return buf.String()
	}

	hasDirective := func(conf, name string) bool {
		for _, line := range strings.Split(conf, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), name+" ") {
				return true
			}
		}
		return false
	}

	standalone := render(true)
	if !strings.Contains(standalone, "cluster-enabled no") {
		t.Errorf("standalone config should set 'cluster-enabled no'")
	}
	if hasDirective(standalone, "cluster-config-file") {
		t.Errorf("standalone config should not set cluster-config-file")
	}
	if hasDirective(standalone, "cluster-preferred-endpoint-type") {
		t.Errorf("standalone config should not set cluster-preferred-endpoint-type")
	}

	cluster := render(false)
	if !strings.Contains(cluster, "cluster-enabled yes") {
		t.Errorf("cluster config should set 'cluster-enabled yes'")
	}
	if !hasDirective(cluster, "cluster-config-file") {
		t.Errorf("cluster config should set cluster-config-file")
	}
}

func TestValidateStandaloneCoercesSingleNode(t *testing.T) {
	r := &ValkeyReconciler{
		GlobalConfig: &globalcfg.Config{
			ValkeyImage:  "valkey",
			SidecarImage: "sidecar",
		},
	}
	valkey := &hyperspikeiov1.Valkey{
		Spec: hyperspikeiov1.ValkeySpec{
			Standalone: true,
			Shards:     3,
			Replicas:   2,
		},
	}
	if err := r.validateValkeySpec(valkey); err != nil {
		t.Fatalf("validateValkeySpec returned error: %v", err)
	}
	if valkey.Spec.Shards != 1 {
		t.Errorf("Expected %v, got %v", 1, valkey.Spec.Shards)
	}
	if valkey.Spec.Replicas != 0 {
		t.Errorf("Expected %v, got %v", 0, valkey.Spec.Replicas)
	}
}
