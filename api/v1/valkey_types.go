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
	SidecarImage string `json:"sidecarImage,omitempty"`

	// Number of shards (IE master nodes)
	// +kubebuilder:default:=3
	Shards int32 `json:"shards,omitempty"`

	// Number of replicas per shard (IE follower nodes)
	// +kubebuilder:default:=0
	Replicas int32 `json:"replicas,omitempty"`

	// Auto Upgrade - Automatically upgrade the Valkey version when a new version is available
	// +kubebuilder:default:=true
	AutoUpgrade bool `json:"autoUpgrade,omitempty"`

	// Auto Scale - Automatically re-scale the number of shards and replicas.
	AutoScaling *AutoScaleSpec `json:"autoScaling,omitempty"`

	// Turn on an init container to set permissions on the persistent volume
	// +kubebuilder:default:=false
	VolumePermissions bool `json:"volumePermissions"`

	// TLS Support
	// +kubebuilder:default:=false
	// +optional
	TLS bool `json:"tls,omitempty"`
	// Certificate Issuer
	// +optional
	CertIssuer string `json:"certIssuer,omitempty"`
	// Certificate Issuer Type
	// +kubebuilder:default:="ClusterIssuer"
	// +kubebuilder:validation:Enum=ClusterIssuer;Issuer
	// +optional
	CertIssuerType string `json:"certIssuerType,omitempty"`

	// Enable prometheus
	// +kubebuilder:default:=false
	Prometheus bool `json:"prometheus"`
	// Extra prometheus labels for operator targeting
	// +optional
	PrometheusLabels map[string]string `json:"prometheusLabels,omitempty"`

	// Cluster Domain - used for DNS
	// +kubebuilder:default:=cluster.local
	ClusterDomain string `json:"clusterDomain"`

	// Persistent volume claim
	// +optional
	Storage *corev1.PersistentVolumeClaim `json:"storage,omitempty"`

	// Resources requirements and limits for the Valkey Server container
	// +optional
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`

	// External access configuration
	// +optional
	ExternalAccess *ExternalAccessSpec `json:"externalAccess,omitempty"`

	// Anonymous Auth
	// +kubebuilder:default:=false
	AnonymousAuth bool `json:"anonymousAuth"`

	// Service Password
	// +optional
	ServicePassword *corev1.SecretKeySelector `json:"servicePassword,omitempty"`

	// Tolerations
	// +optional
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`

	// Node Selector
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// Which endpoint is shown as the preferred endpoint valid values are 'ip', 'hostname', or 'unknown-endpoint'.
	// +kubebuilder:default:="ip"
	// +kubebuilder:validation:Enum=ip;hostname;unknown-endpoint
	// +optional
	ClusterPreferredEndpointType string `json:"clusterPreferredEndpointType,omitempty"`
}

// AutoScaleSpec defines the autoscale configuration
type AutoScaleSpec struct {
	// Enable auto scaling
	// +kubebuilder:default:=false
	Enabled bool `json:"enabled,omitempty"`

	// Minimum number of shards
	// +kubebuilder:default:=3
	MinShards int32 `json:"minShards,omitempty"`

	// Maximum number of shards
	// +kubebuilder:default:=5
	MaxShards int32 `json:"maxShards,omitempty"`

	// Minimum number of replicas
	// +kubebuilder:default:=0
	MinReplicas int32 `json:"minReplicas,omitempty"`

	// Maximum number of replicas
	// +kubebuilder:default:=3
	MaxReplicas int32 `json:"maxReplicas,omitempty"`

	// CPU threshold for scaling
	// +kubebuilder:default:=80
	CPUThreshold int32 `json:"cpuThreshold,omitempty"`

	// Memory threshold for scaling
	// +kubebuilder:default:=80
	MemoryThreshold int32 `json:"memoryThreshold,omitempty"`

	// Scale up delay
	// +kubebuilder:default:="1m"
	ScaleUpDelay string `json:"scaleUpDelay,omitempty"`

	// Scale down delay
	// +kubebuilder:default:="45s"
	ScaleDownDelay string `json:"scaleDownDelay,omitempty"`
}

// ExternalAccess defines the external access configuration
type ExternalAccessSpec struct {
	// Enable external access
	// +kubebuilder:default:=false
	Enabled bool `json:"enabled"`

	// External access type
	// LoadBalancer or Proxy, the LoadBalancer type will create a LoadBalancer service for each Valkey Shard (master node)
	// The Proxy type will create a single LoadBalancer service and use an envoy proxy to route traffic to the Valkey Shards
	// +kubebuilder:default:=Proxy
	// +kubebuilder:validation:Enum=LoadBalancer;Proxy
	Type string `json:"type"`

	// Proxy Settings
	// +optional
	Proxy *ProxySettings `json:"proxy,omitempty"`

	// LoadBalancer Settings
	LoadBalancer *LoadBalancerSettings `json:"loadBalancer,omitempty"`

	// Cert Issuer for external access TLS certificate
	// +optional
	CertIssuer string `json:"certIssuer,omitempty"`

	// Cert Issuer Type for external access TLS certificate
	// +kubebuilder:default:="ClusterIssuer"
	// +kubebuilder:validation:Enum=ClusterIssuer;Issuer
	// +optional
	CertIssuerType string `json:"certIssuerType,omitempty"`

	// Support External DNS
	// +kubebuilder:default:=false
	// +optional
	ExternalDNS bool `json:"externalDNS,omitempty"`
}

// ProxySettings defines the proxy settings
type ProxySettings struct {
	// Image to use for the proxy
	// +kubebuilder:default:="envoyproxy/envoy:v1.32.1"
	// +optional
	Image string `json:"image,omitempty"`
	// Resources requirements and limits for the proxy container
	// +optional
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`

	// Extra Envoy configuration
	// +optional
	ExtraConfig string `json:"extraConfig,omitempty"`

	// Annotations for the proxy service
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`

	// Replicas for the proxy
	// +kubebuilder:default:=1
	Replicas *int32 `json:"replicas"`

	// External Hostname for the proxy
	// +optional
	Hostname string `json:"hostname,omitempty"`
}

// LoadBalancerSettings defines the load balancer settings
type LoadBalancerSettings struct {
	// Annotations for the load balancer service
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`
}

// ValkeyStatus defines the observed state of Valkey
type ValkeyStatus struct {
	// Important: Run "make" to regenerate code after modifying this file
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type" protobuf:"bytes,1,rep,name=conditions"`
	Ready      bool               `json:"ready"`
	Shards     int32              `json:"shards"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:subresource:scale:specpath=.spec.shards,statuspath=.status.shards
// +kubebuilder:resource:shortName=vk

// Valkey is the Schema for the valkeys API
// +kubebuilder:printcolumn:name="Ready",type="boolean",JSONPath=`.status.ready`
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:printcolumn:name="Shards",type="integer",JSONPath=".spec.shards"
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
