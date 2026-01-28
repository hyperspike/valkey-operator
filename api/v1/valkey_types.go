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

// RDBSpec defines the RDB persistence configuration
type RDBSpec struct {
	// Enable RDB persistence
	// +kubebuilder:default:=true
	// +optional
	Enabled *bool `json:"enabled,omitempty"`

	// Save rules for RDB snapshots. Each rule is in the format "seconds changes".
	// Example: ["900 1", "300 10", "60 10000"] means save after 900s if 1 key changed,
	// after 300s if 10 keys changed, or after 60s if 10000 keys changed.
	// +optional
	SaveRules []string `json:"saveRules,omitempty"`

	// Compress string objects using LZF when dumping RDB files
	// +kubebuilder:default:=true
	// +optional
	Compression *bool `json:"compression,omitempty"`

	// Enable CRC64 checksum at the end of RDB files
	// +kubebuilder:default:=true
	// +optional
	Checksum *bool `json:"checksum,omitempty"`

	// Stop accepting writes if RDB snapshots are enabled and the latest background save failed
	// +kubebuilder:default:=true
	// +optional
	StopWritesOnBgSaveError *bool `json:"stopWritesOnBgSaveError,omitempty"`
}

// AOFSpec defines the AOF (Append Only File) persistence configuration
type AOFSpec struct {
	// Enable AOF persistence
	// +kubebuilder:default:=false
	// +optional
	Enabled *bool `json:"enabled,omitempty"`

	// Fsync policy: "always", "everysec", or "no"
	// - always: fsync after every write (slow, safest)
	// - everysec: fsync once per second (compromise)
	// - no: let the OS flush when it wants (faster, less safe)
	// +kubebuilder:default:="everysec"
	// +kubebuilder:validation:Enum=always;everysec;no
	// +optional
	Fsync string `json:"fsync,omitempty"`

	// Don't fsync during AOF rewrite/RDB save to avoid blocking
	// +kubebuilder:default:=false
	// +optional
	NoAppendFsyncOnRewrite *bool `json:"noAppendFsyncOnRewrite,omitempty"`

	// Automatic AOF rewrite percentage. Rewrite when AOF grows by this percentage.
	// Set to 0 to disable auto-rewrite.
	// +kubebuilder:default:=100
	// +optional
	AutoRewritePercentage *int32 `json:"autoRewritePercentage,omitempty"`

	// Minimum size for AOF file to be rewritten
	// +kubebuilder:default:="64mb"
	// +optional
	AutoRewriteMinSize string `json:"autoRewriteMinSize,omitempty"`

	// Load truncated AOF file on startup instead of failing
	// +kubebuilder:default:=true
	// +optional
	LoadTruncated *bool `json:"loadTruncated,omitempty"`

	// Use RDB preamble in AOF for faster loading
	// +kubebuilder:default:=true
	// +optional
	UseRDBPreamble *bool `json:"useRDBPreamble,omitempty"`
}

// PersistenceSpec defines the persistence configuration for Valkey
type PersistenceSpec struct {
	// RDB persistence configuration
	// +optional
	RDB *RDBSpec `json:"rdb,omitempty"`

	// AOF persistence configuration
	// +optional
	AOF *AOFSpec `json:"aof,omitempty"`
}

// ValkeySpec defines the desired state of Valkey
type ValkeySpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// Image to use
	Image string `json:"image,omitempty"`

	// Exporter Image to use
	ExporterImage string `json:"exporterImage,omitempty"`

	// Number of shards. Each node is a primary
	// +kubebuilder:default:=3
	Shards int32 `json:"nodes,omitempty"`

	// Number of replicas for each node.
	//
	// Note: This field currently creates extra primary nodes.
	// Follow  https://github.com/hyperspike/valkey-operator/issues/186 for details
	//
	// +kubebuilder:default:=0
	Replicas int32 `json:"replicas,omitempty"`

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

	// ServiceMonitor Enabled. The service monitor is a custom resource which tells
	// other Prometheus components how to scrape metrics from the valkey cluster
	// +kubebuilder:default:=false
	ServiceMonitor bool `json:"serviceMonitor"`

	// Cluster Domain - used for DNS
	// +kubebuilder:default:=cluster.local
	ClusterDomain string `json:"clusterDomain"`

	// Persistent volume claim. The kind and metadata can be omitted, but the spec
	// is necessary.
	// +optional
	Storage *corev1.PersistentVolumeClaim `json:"storage,omitempty"`

	// Persistence configuration for RDB and AOF
	// +optional
	Persistence *PersistenceSpec `json:"persistence,omitempty"`

	// Resources requirements and limits for the Valkey Server container
	// +optional
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`

	// External access configuration
	// +optional
	ExternalAccess *ExternalAccess `json:"externalAccess,omitempty"`

	// Anonymous Auth.
	//
	// If true, clients can login without providing a password. If
	// false, the the operator will configure the valkey server to use a password. It
	// will either create a Secret holding the password or, if ServicePassword is set,
	// use an existing secret.
	//
	// +kubebuilder:default:=false
	AnonymousAuth bool `json:"anonymousAuth"`

	// Service Password is a SecretKeySelector that points to a data key in a Secret. Look for
	// SecretKeySelector in [Kubernetes Pod Documentation] for details
	//
	// This field is optional. If ServicePassword is not set and
	// [ValkeySpec.AnonymousAuth] is false, then the operator will create a secret
	// in with the same name and  namespace as the custom resource, with a "password" data key
	// and a random 16-character password value.
	//
	// https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#environment-variables
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

	// PlatformManagedSecurityContext delegates security context management to the platform.
	// When true, the operator omits the following fields from pod and container security contexts,
	// allowing the platform (e.g., OpenShift) to manage them via SCCs or Pod Security Standards:
	// - RunAsUser, RunAsGroup, FSGroup (user/group IDs)
	// - FSGroupChangePolicy, SupplementalGroups
	// - SELinuxOptions
	// When false (default), these fields are set to explicit values (e.g., 1001 for user/group IDs).
	// +kubebuilder:default:=false
	// +optional
	PlatformManagedSecurityContext bool `json:"platformManagedSecurityContext,omitempty"`
}

// ExternalAccess defines the external access configuration
type ExternalAccess struct {
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
