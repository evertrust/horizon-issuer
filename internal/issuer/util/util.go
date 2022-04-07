/*
Copyright 2020 The cert-manager Authors

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

package util

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	horizonapi "github.com/evertrust/horizon-issuer/api/v1alpha1"
)

func GetSpecAndStatus(issuer client.Object) (*horizonapi.IssuerSpec, *horizonapi.IssuerStatus, error) {
	switch t := issuer.(type) {
	case *horizonapi.Issuer:
		return &t.Spec, &t.Status, nil
	case *horizonapi.ClusterIssuer:
		return &t.Spec, &t.Status, nil
	default:
		return nil, nil, fmt.Errorf("not an issuer type: %t", t)
	}
}

func SetReadyCondition(status *horizonapi.IssuerStatus, conditionStatus horizonapi.ConditionStatus, reason, message string) {
	ready := GetReadyCondition(status)
	if ready == nil {
		ready = &horizonapi.IssuerCondition{
			Type: horizonapi.IssuerConditionReady,
		}
		status.Conditions = append(status.Conditions, *ready)
	}
	if ready.Status != conditionStatus {
		ready.Status = conditionStatus
		now := metav1.Now()
		ready.LastTransitionTime = &now
	}
	ready.Reason = reason
	ready.Message = message

	for i, c := range status.Conditions {
		if c.Type == horizonapi.IssuerConditionReady {
			status.Conditions[i] = *ready
			return
		}
	}
}

func GetReadyCondition(status *horizonapi.IssuerStatus) *horizonapi.IssuerCondition {
	for _, c := range status.Conditions {
		if c.Type == horizonapi.IssuerConditionReady {
			return &c
		}
	}
	return nil
}

func IsReady(status *horizonapi.IssuerStatus) bool {
	if c := GetReadyCondition(status); c != nil {
		return c.Status == horizonapi.ConditionTrue
	}
	return false
}
