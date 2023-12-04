/*
Copyright 2022.

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

// IssuerStatus defines the observed state of Issuer
type IssuerStatus struct {
	// List of status conditions to indicate the status of a CertificateRequest.
	// Known condition types are `Ready`.
	// +optional
	Conditions []IssuerCondition `json:"conditions,omitempty"`
}

// Issuer is the Schema for the issuers API
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion
// +kubebuilder:printcolumn:name="Profile",type=string,JSONPath=`.spec.profile`
// +kubebuilder:printcolumn:name="Horizon URL",type=string,JSONPath=`.spec.url`
// +kubebuilder:printcolumn:name="Secret",type=string,JSONPath=`.spec.authSecretName`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=='Ready')].status`
type Issuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   IssuerSpec   `json:"spec,omitempty"`
	Status IssuerStatus `json:"status,omitempty"`
}

// IssuerList contains a list of Issuer
// +kubebuilder:object:root=true
type IssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Issuer `json:"items"`
}

// IssuerCondition contains condition information for an Issuer.
type IssuerCondition struct {
	// Type of the condition, known values are ('Ready').
	Type IssuerConditionType `json:"type"`

	// Status of the condition, one of ('True', 'False', 'Unknown').
	Status ConditionStatus `json:"status"`

	// LastTransitionTime is the timestamp corresponding to the last status
	// change of this condition.
	// +optional
	LastTransitionTime *metav1.Time `json:"lastTransitionTime,omitempty"`

	// Reason is a brief machine readable explanation for the condition's last
	// transition.
	// +optional
	Reason string `json:"reason,omitempty"`

	// Message is a human readable description of the details of the last
	// transition, complementing reason.
	// +optional
	Message string `json:"message,omitempty"`
}

// IssuerConditionType represents an Issuer condition value.
type IssuerConditionType string

const (
	// IssuerConditionReady represents the fact that a given Issuer condition
	// is in ready state and able to issue certificates.
	// If the `status` of this condition is `False`, CertificateRequest controllers
	// should prevent attempts to sign certificates.
	IssuerConditionReady IssuerConditionType = "Ready"
)

// ConditionStatus represents a condition's status.
// +kubebuilder:validation:Enum=True;False;Unknown
type ConditionStatus string

// These are valid condition statuses. "ConditionTrue" means a resource is in
// the condition; "ConditionFalse" means a resource is not in the condition;
// "ConditionUnknown" means kubernetes can't decide if a resource is in the
// condition or not. In the future, we could add other intermediate
// conditions, e.g. ConditionDegraded.
const (
	// ConditionTrue represents the fact that a given condition is true
	ConditionTrue ConditionStatus = "True"

	// ConditionFalse represents the fact that a given condition is false
	ConditionFalse ConditionStatus = "False"

	// ConditionUnknown represents the fact that a given condition is unknown
	ConditionUnknown ConditionStatus = "Unknown"
)

func init() {
	SchemeBuilder.Register(&Issuer{}, &IssuerList{})
}
