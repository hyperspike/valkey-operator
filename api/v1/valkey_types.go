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
	Image string `json:"image,omitempty"`

	// Exporter Image to use
	ExporterImage string `json:"exporterImage,omitempty"`

	// Number of shards
	// +kubebuilder:default:=3
	Shards int32 `json:"nodes,omitempty"`

	// Number of replicas
	// +kubebuilder:default:=0
	Replicas int32 `json:"replicas,omitempty"`

	// Turn on an init container to set permissions on the persistent volume
	// +kubebuilder:default:=false
	VolumePermissions bool `json:"volumePermissions,omitempty"`

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

	// Resources requirements and limits for the Valkey Server container
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`

	// External access configuration
	ExternalAccess *ExternalAccess `json:"externalAccess,omitempty"`
}

// ExternalAccess defines the external access configuration
type ExternalAccess struct {
	// Enable external access
	// +kubebuilder:default:=false
	Enabled bool `json:"enabled,omitempty"`

	// External access type
	// LoadBalancer or Proxy, the LoadBalancer type will create a LoadBalancer service for each Valkey Shard (master node)
	// The Proxy type will create a single LoadBalancer service and use an envoy proxy to route traffic to the Valkey Shards
	// +kubebuilder:default:=Proxy
	// +kubebuilder:validation:Enum=LoadBalancer;Proxy
	Type string `json:"type,omitempty"`

	// Proxy Settings
	Proxy *ProxySettings `json:"proxy,omitempty"`

	// LoadBalancer Settings
	LoadBalancer *LoadBalancerSettings `json:"loadBalancer,omitempty"`

	// Cert Issuer for external access TLS certificate
	CertIssuer string `json:"certIssuer,omitempty"`

	// Cert Issuer Type for external access TLS certificate
	// +kubebuilder:default:="ClusterIssuer"
	// +kubebuilder:validation:Enum=ClusterIssuer;Issuer
	CertIssuerType string `json:"certIssuerType,omitempty"`

	// Support External DNS
	// +kubebuilder:default:=false
	ExternalDNS bool `json:"externalDNS,omitempty"`
}

// ProxySettings defines the proxy settings
type ProxySettings struct {
	// Image to use for the proxy
	// +kubebuilder:default:="envoyproxy/envoy:v1.32.1"
	Image string `json:"image,omitempty"`
	// Resources requirements and limits for the proxy container
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`

	// Extra Envoy configuration
	ExtraConfig string `json:"extraConfig,omitempty"`

	// Annotations for the proxy service
	Annotations map[string]string `json:"annotations,omitempty"`

	// Replicas for the proxy
	// +kubebuilder:default:=1
	Replicas *int32 `json:"replicas,omitempty"`

	// External Hostname for the proxy
	Hostname string `json:"hostname,omitempty"`
}

// LoadBalancerSettings defines the load balancer settings
type LoadBalancerSettings struct {
	// Annotations for the load balancer service
	Annotations map[string]string `json:"annotations,omitempty"`
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
// +kubebuilder:printcolumn:name="Volumme Permissions",type="boolean",priority=1,JSONPath=".spec.volumePermissions"
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
