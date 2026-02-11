/*
Copyright 2025.

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

package v1beta1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// IssuerSpec defines the desired state of Issuer
type IssuerSpec struct {
	// URL is the base URL of your Horizon instance,
	// for instance: "https://horizon.yourcompany.com".
	URL string `json:"url"`

	// Proxy is the URL of a proxy to use to reach the Horizon instance.
	Proxy *string `json:"proxy,omitempty"`

	// The Horizon Profile that will be used to enroll certificates. Your
	// authenticated principal should have rights over this Profile.
	Profile string `json:"profile"`

	// A reference to a Secret in the same namespace as the referent. If the
	// referent is a ClusterIssuer, the reference instead refers to the resource
	// with the given name in the configured 'cluster resource namespace', which
	// is set as a flag on the controller component (and defaults to the
	// namespace that the controller runs in).
	AuthSecretName string `json:"authSecretName"`

	// CaBundle contains the CA bundle required to
	// trust the Horizon endpoint certificate
	// +optional
	CaBundle *string `json:"caBundle,omitempty"`

	// SkipTLSVerify indicates if untrusted certificates should be allowed
	// when connecting to the Horizon instance.
	// +optional
	// +kubebuilder:default:=false
	SkipTLSVerify bool `json:"skipTLSVerify"`

	// RevokeCertificates controls whether this issuer should revoke certificates
	// that have been issued through it when their Kubernetes object is deleted.
	// +kubebuilder:default:=false
	// +optional
	RevokeCertificates bool `json:"revokeCertificates"`

	// DefaultTemplate is the default template that will be used to
	// issue certificates. Values specified here will not override any
	// values set in the Certificate or Issuer objects.
	DefaultTemplate *IssuerTemplate `json:"defaultTemplate,omitempty"`

	// OverrideTemplate is the enforced template that will be used to
	// issue certificates. Values specified here will override any values
	// set in the Certificate or Issuer objects.
	OverrideTemplate *IssuerTemplate `json:"overrideTemplate,omitempty"`

	// DnsChecker indicates that the issuer should
	// validate that the DNS record associated with a certificate
	DnsChecker *IssuerDnsChecker `json:"dnsChecker,omitempty"`
}

type IssuerTemplate struct {
	// Labels is a map of labels that that
	// will be attached to issued certificates.
	Labels map[string]string `json:"labels,omitempty"`

	// Owner will set the certificate ownership to the given value.
	Owner *string `json:"owner,omitempty"`

	// Team will set the certificate ownership to the given team.
	Team *string `json:"team,omitempty"`

	// ContactEmail will set the contact email for the certificate.
	ContactEmail *string `json:"contactEmail,omitempty"`
}

type IssuerDnsChecker struct {
	Server string `json:"server"`
}

// IssuerStatus defines the observed state of Issuer.
type IssuerStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// For Kubernetes API conventions, see:
	// https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#typical-status-properties

	// conditions represent the current state of the Issuer resource.
	// Each condition has a unique type and reflects the status of a specific aspect of the resource.
	//
	// Standard condition types include:
	// - "Available": the resource is fully functional
	// - "Progressing": the resource is being created or updated
	// - "Degraded": the resource failed to reach or maintain its desired state
	//
	// The status of each condition is one of True, False, or Unknown.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion
// +kubebuilder:printcolumn:name="Profile",type=string,JSONPath=`.spec.profile`
// +kubebuilder:printcolumn:name="Horizon URL",type=string,JSONPath=`.spec.url`
// +kubebuilder:printcolumn:name="Secret",type=string,JSONPath=`.spec.authSecretName`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=='Ready')].status`

// Issuer is the Schema for the issuers API
type Issuer struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of Issuer
	// +required
	Spec IssuerSpec `json:"spec"`

	// status defines the observed state of Issuer
	// +optional
	Status IssuerStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// IssuerList contains a list of Issuer
type IssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []Issuer `json:"items"`
}

// IssuerConditionType is the string key for a condition in .status.conditions.type.
type IssuerConditionType string

const (
	// IssuerConditionReady represents readiness to issue certificates.
	IssuerConditionReady IssuerConditionType = "Ready"
	// IssuerConditionError represents an error in reaching the issuer.
	IssuerConditionError IssuerConditionType = "Error"
)

func init() {
	SchemeBuilder.Register(&Issuer{}, &IssuerList{})
}
