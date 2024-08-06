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

package v1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// ValkeySpec defines the desired state of Valkey
type ValkeySpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// Image to use
	// +kubebuilder:default:="docker.io/bitnami/valkey-cluster:7.2.6-debian-12-r0"
	Image string `json:"image,omitempty"`

	// Number of nodes
	// +kubebuilder:default:=3
	Nodes int32 `json:"nodes,omitempty"`

	// Number of replicas
	// +kubebuilder:default:=0
	Replicas int32 `json:"replicas,omitempty"`

	// Rootless mode
	// +kubebuilder:default:=true
	Rootless bool `json:"rootless,omitempty"`

	// TLS Support
	// +kubebuilder:default:=false
	TLS bool `json:"tls,omitempty"`
	// Certificate Issuer
	CertIssuer string `json:"certIssuer,omitempty"`
	// Certificate Issuer Type
	// +kubebuilder:default:="ClusterIssuer"
	// +kubebuilder:validation:Enum=ClusterIssuer;Issuer
	CertIssuerType string `json:"certIssuerType,omitempty"`

	// Enable prometheus
	// +kubebuilder:default:=false
	Prometheus bool `json:"prometheus,omitempty"`
	// Extra prometheus labels for operator targeting
	PrometheusLabels map[string]string `json:"prometheusLabels,omitempty"`

	// Cluster Domain - used for DNS
	// +kubebuilder:default:=cluster.local
	ClusterDomain string `json:"clusterDomain,omitempty"`

	// Persistent volume claim
	Storage *corev1.PersistentVolumeClaim `json:"storage,omitempty"`
}

// ValkeyStatus defines the observed state of Valkey
type ValkeyStatus struct {
	// Important: Run "make" to regenerate code after modifying this file
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type" protobuf:"bytes,1,rep,name=conditions"`
	Ready      bool               `json:"ready"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=vk

// Valkey is the Schema for the valkeys API
// +kubebuilder:printcolumn:name="Ready",type="boolean",JSONPath=`.status.ready`
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:printcolumn:name="Nodes",type="integer",JSONPath=".spec.nodes"
// +kubebuilder:printcolumn:name="Replicas",type="integer",JSONPath=".spec.replicas"
// +kubebuilder:printcolumn:name="Rootless",type="boolean",priority=1,JSONPath=".spec.rootless"
// +kubebuilder:printcolumn:name="Image",type="string",priority=1,JSONPath=".spec.image"
type Valkey struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ValkeySpec   `json:"spec,omitempty"`
	Status ValkeyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ValkeyList contains a list of Valkey
type ValkeyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Valkey `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Valkey{}, &ValkeyList{})
}
