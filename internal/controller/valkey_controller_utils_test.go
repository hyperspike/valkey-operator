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
	"testing"

	hyperspikeiov1 "hyperspike.io/valkey-operator/api/v1"
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

func TestResolveEndpointType(t *testing.T) {
	tests := []struct {
		name     string
		spec     hyperspikeiov1.ValkeySpec
		expected string
	}{
		{
			name:     "defaults to ip when nothing is set",
			spec:     hyperspikeiov1.ValkeySpec{},
			expected: "ip",
		},
		{
			name:     "respects ClusterPreferredEndpointType=hostname",
			spec:     hyperspikeiov1.ValkeySpec{ClusterPreferredEndpointType: "hostname"},
			expected: "hostname",
		},
		{
			name:     "respects ClusterPreferredEndpointType=ip explicitly",
			spec:     hyperspikeiov1.ValkeySpec{ClusterPreferredEndpointType: "ip"},
			expected: "ip",
		},
		{
			name:     "TLS overrides ClusterPreferredEndpointType to hostname",
			spec:     hyperspikeiov1.ValkeySpec{TLS: true, ClusterPreferredEndpointType: "ip"},
			expected: "hostname",
		},
		{
			name:     "TLS implies hostname even when ClusterPreferredEndpointType is unset",
			spec:     hyperspikeiov1.ValkeySpec{TLS: true},
			expected: "hostname",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valkey := &hyperspikeiov1.Valkey{
				ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"},
				Spec:       tt.spec,
			}
			result := resolveEndpointType(valkey)
			if result != tt.expected {
				t.Errorf("resolveEndpointType() = %q, want %q", result, tt.expected)
			}
		})
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
