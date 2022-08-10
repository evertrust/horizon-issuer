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

package controllers

import (
	"context"
	"errors"
	"fmt"
	cmutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/evertrust/horizon-go/http"
	"github.com/evertrust/horizon-go/requests"
	horizonapi "github.com/evertrust/horizon-issuer/api/v1alpha1"
	horizonissuer "github.com/evertrust/horizon-issuer/internal/issuer/horizon"
	issuerutil "github.com/evertrust/horizon-issuer/internal/issuer/util"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/clock"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"reflect"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

var (
	errIssuerRef      = errors.New("error interpreting issuerRef")
	errGetIssuer      = errors.New("error getting issuer")
	errIssuerNotReady = errors.New("issuer is not ready")
)

const FinalizerName = horizonissuer.IssuerNamespace + "/finalizer"

// CertificateRequestReconciler reconciles a CertificateRequest object
type CertificateRequestReconciler struct {
	client.Client
	Scheme                   *runtime.Scheme
	ClusterResourceNamespace string
	Clock                    clock.Clock
	Issuer                   horizonissuer.HorizonIssuer
}

func (r *CertificateRequestReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, err error) {
	log := ctrl.LoggerFrom(ctx)

	// Get the CertificateRequest
	var certificateRequest cmapi.CertificateRequest
	if err := r.Get(ctx, req.NamespacedName, &certificateRequest); err != nil {
		if err := client.IgnoreNotFound(err); err != nil {
			return ctrl.Result{}, fmt.Errorf("unexpected get error: %v", err)
		}
		log.V(1).Info("Not found. Ignoring.")
		return ctrl.Result{}, nil
	}

	// Ignore CertificateRequest if issuerRef doesn't match our group
	if certificateRequest.Spec.IssuerRef.Group != horizonapi.GroupVersion.Group {
		log.V(1).Info("Foreign group. Ignoring.", "group", certificateRequest.Spec.IssuerRef.Group)
		return ctrl.Result{}, nil
	}

	// We now have a CertificateRequest that belongs to us so we are responsible
	// for updating its Ready condition.
	setReadyCondition := func(status cmmeta.ConditionStatus, reason, message string) {
		cmutil.SetCertificateRequestCondition(
			&certificateRequest,
			cmapi.CertificateRequestConditionReady,
			status,
			reason,
			message,
		)
	}

	issuer, err := r.issuerFromRequest(ctx, &certificateRequest)
	if err != nil {
		log.Error(err, "Cannot find Issuer")
		return ctrl.Result{}, fmt.Errorf("%w", err)
	}

	var secretNamespace string
	switch issuer.(type) {
	case *horizonapi.Issuer:
		secretNamespace = certificateRequest.Namespace
		log = log.WithValues("issuer", issuer.GetName())
	case *horizonapi.ClusterIssuer:
		secretNamespace = r.ClusterResourceNamespace
		log = log.WithValues("clusterissuer", issuer.GetName())
	default:
		return ctrl.Result{}, nil
	}

	issuerSpec, issuerStatus, err := issuerutil.GetSpecAndStatus(issuer)
	if err != nil {
		log.Error(err, "Unable to get the IssuerStatus. Ignoring.")
		setReadyCondition(cmmeta.ConditionFalse, cmapi.CertificateRequestReasonFailed, err.Error())
		return ctrl.Result{}, nil
	}

	if !issuerutil.IsReady(issuerStatus) {
		log.V(1).Info("Issuer not ready")
		return ctrl.Result{}, nil
	}

	secretName := types.NamespacedName{
		Name:      issuerSpec.AuthSecretName,
		Namespace: secretNamespace,
	}

	var secret corev1.Secret

	err = r.Get(ctx, secretName, &secret)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("%w, secret name: %s, reason: %v", errGetAuthSecret, secretName, err)
	}

	// From here, we're ready to instantiate a Horizon client
	clientFromIssuer, err := horizonissuer.ClientFromIssuer(issuerSpec, secret.Data)
	if err != nil || clientFromIssuer == nil {
		return ctrl.Result{}, fmt.Errorf("%s: %v", "Unable to instantiate an Horizon client", err)
	}

	r.Issuer.Client = *clientFromIssuer

	if issuerSpec.RevokeCertificates {
		// examine DeletionTimestamp to determine if object is under deletion
		if certificateRequest.ObjectMeta.DeletionTimestamp.IsZero() {
			// The object is not being deleted, so if it does not have our finalizer,
			// then lets add the finalizer and update the object. This is equivalent
			// registering our finalizer.
			if !controllerutil.ContainsFinalizer(&certificateRequest, FinalizerName) {
				controllerutil.AddFinalizer(&certificateRequest, FinalizerName)
			}
		} else {
			// The object is being deleted
			err = r.handleDeletion(ctx, &certificateRequest)
			if err != nil {
				return ctrl.Result{}, err
			}
			// Stop reconciliation as the item is being deleted
			return ctrl.Result{}, nil
		}
	}

	// Ignore CertificateRequest if it is already Ready
	if cmutil.CertificateRequestHasCondition(&certificateRequest, cmapi.CertificateRequestCondition{
		Type:   cmapi.CertificateRequestConditionReady,
		Status: cmmeta.ConditionTrue,
	}) {
		log.V(1).Info("CertificateRequest is Ready. Ignoring.")
		return ctrl.Result{}, nil
	}
	// Ignore CertificateRequest if it is already Failed
	if cmutil.CertificateRequestHasCondition(&certificateRequest, cmapi.CertificateRequestCondition{
		Type:   cmapi.CertificateRequestConditionReady,
		Status: cmmeta.ConditionFalse,
		Reason: cmapi.CertificateRequestReasonFailed,
	}) {
		log.V(1).Info("CertificateRequest is Failed. Ignoring.")
		return ctrl.Result{}, nil
	}
	// Ignore CertificateRequest if it already has a Denied Ready Reason
	if cmutil.CertificateRequestHasCondition(&certificateRequest, cmapi.CertificateRequestCondition{
		Type:   cmapi.CertificateRequestConditionReady,
		Status: cmmeta.ConditionFalse,
		Reason: cmapi.CertificateRequestReasonDenied,
	}) {
		log.V(1).Info("CertificateRequest already has a Ready condition with Denied Reason. Ignoring.")
		return ctrl.Result{}, nil
	}

	certificateRequestCopy := certificateRequest.DeepCopy()

	// Update the CSR object when returning from the Reconcile function
	defer func() {
		if err != nil {
			setReadyCondition(cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, err.Error())
		}

		var updateErr error

		// if annotations changed we have to call .Update() and not .UpdateStatus()
		if !reflect.DeepEqual(certificateRequestCopy.Annotations, certificateRequest.Annotations) {
			updateErr = r.Update(ctx, &certificateRequest)
		} else {
			updateErr = r.Status().Update(ctx, &certificateRequest)
		}

		if updateErr != nil {
			err = utilerrors.NewAggregate([]error{err, updateErr})
			result = ctrl.Result{}
		}
	}()

	// If CertificateRequest has been denied, mark the CertificateRequest as
	// Ready=Denied and set FailureTime if not already.
	if cmutil.CertificateRequestIsDenied(&certificateRequest) {
		log.Info("CertificateRequest has been denied yet. Marking as failed.")

		if certificateRequest.Status.FailureTime == nil {
			nowTime := metav1.NewTime(r.Clock.Now())
			certificateRequest.Status.FailureTime = &nowTime
		}

		message := "The CertificateRequest was denied by an approval controller"
		setReadyCondition(cmmeta.ConditionFalse, cmapi.CertificateRequestReasonDenied, message)
		return ctrl.Result{}, nil
	}

	// If CertificateRequest has not been approved, we should submit the request.
	if !cmutil.CertificateRequestIsApproved(&certificateRequest) {
		// If the request has been submitted to Horizon, pull info from Horizon
		if _, ok := certificateRequest.Annotations[horizonissuer.RequestIdAnnotation]; ok {
			return r.Issuer.UpdateRequest(ctx, &certificateRequest)
		} else {
			labels, owner, team, err := r.certificateMetadata(ctx, &certificateRequest)
			if err != nil {
				setReadyCondition(cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, err.Error())
			}
			return r.Issuer.SubmitRequest(ctx, r.Client, *issuerSpec, labels, owner, team, &certificateRequest)
		}
	}

	return ctrl.Result{}, nil
}

func (r *CertificateRequestReconciler) handleDeletion(ctx context.Context, certificateRequest *cmapi.CertificateRequest) error {
	if controllerutil.ContainsFinalizer(certificateRequest, FinalizerName) {
		// our finalizer is present, so lets handle any external dependency
		if err := r.Issuer.RevokeCertificate(ctx, certificateRequest); err != nil {
			// if fail to delete the external dependency here, return with error
			// so that it can be retried, except if the error is from Horizon
			if _, isHorizonError := err.(*http.HorizonErrorResponse); !isHorizonError {
				return err
			} else {
				ctrl.LoggerFrom(ctx).Info(fmt.Sprintf("Horizon returned an error when revoking the certificate : %s. Marking the certificate as revoked to avoid a loop.", err.Error()))
			}
		}

		// remove our finalizer from the list and update it.
		controllerutil.RemoveFinalizer(certificateRequest, FinalizerName)
	}

	return nil
}

func (r *CertificateRequestReconciler) certificateMetadata(ctx context.Context, certificateRequest *cmapi.CertificateRequest) ([]requests.LabelElement, *string, *string, error) {
	// Récupérer le certificat
	var owner *string
	var team *string
	var labels []requests.LabelElement

	certificate, err := r.certificateFromRequest(ctx, certificateRequest)
	if err != nil {
		return nil, nil, nil, err
	}
	issuer, err := r.issuerFromRequest(ctx, certificateRequest)
	if err != nil {
		return nil, nil, nil, err
	}
	ingress, err := r.ingressFromCertificate(ctx, certificate)
	if err != nil {
		return nil, nil, nil, err
	}

	if ingress != nil {
		ownerString := ingress.Annotations[horizonissuer.OwnerAnnotation]
		if ownerString != "" {
			owner = &ownerString
		}
		teamString := ingress.Annotations[horizonissuer.TeamAnnotation]
		if teamString != "" {
			owner = &teamString
		}
	}

	if certificate != nil {
		ownerString := certificate.Annotations[horizonissuer.OwnerAnnotation]
		if ownerString != "" {
			owner = &ownerString
		}
		teamString := certificate.Annotations[horizonissuer.TeamAnnotation]
		if teamString != "" {
			owner = &teamString
		}
	}

	issuerSpec, _, err := issuerutil.GetSpecAndStatus(issuer)
	if err != nil {
		return nil, nil, nil, err
	}

	if issuerSpec.Owner != nil {
		owner = issuerSpec.Owner
	}

	if issuerSpec.Team != nil {
		team = issuerSpec.Team
	}

	if len(issuerSpec.Labels) > 0 {
		for k, v := range issuerSpec.Labels {
			labels = append(labels, requests.LabelElement{
				Label: k,
				Value: v,
			})
		}
	}

	return labels, owner, team, nil
}

// issuerFromRequest returns the Issuer of a given CertificateRequest.
func (r *CertificateRequestReconciler) issuerFromRequest(ctx context.Context, certificateRequest *cmapi.CertificateRequest) (client.Object, error) {
	issuerGVK := horizonapi.GroupVersion.WithKind(certificateRequest.Spec.IssuerRef.Kind)
	issuerRO, err := r.Scheme.New(issuerGVK)
	if err != nil {
		err = fmt.Errorf("%w: %v", errIssuerRef, err)
		return nil, err
	}
	issuer := issuerRO.(client.Object)
	// Create a Namespaced name for Issuer and a non-Namespaced name for ClusterIssuer
	issuerName := types.NamespacedName{
		Name: certificateRequest.Spec.IssuerRef.Name,
	}
	switch t := issuer.(type) {
	case *horizonapi.Issuer:
		issuerName.Namespace = certificateRequest.Namespace
	case *horizonapi.ClusterIssuer:
	default:
		err := fmt.Errorf("unexpected issuer type: %v", t)
		return nil, err
	}

	// Get the Issuer or ClusterIssuer
	if err := r.Get(ctx, issuerName, issuer); err != nil {
		return nil, fmt.Errorf("%w: %v", errGetIssuer, err)
	}

	return issuer, nil

}

// certificateFromRequest returns the Certificate object associated with that CertificateRequest
func (r *CertificateRequestReconciler) certificateFromRequest(ctx context.Context, certificateRequest *cmapi.CertificateRequest) (*cmapi.Certificate, error) {
	certificateName := types.NamespacedName{
		Namespace: certificateRequest.Namespace,
		Name:      certificateRequest.Annotations["cert-manager.io/certificate-name"],
	}

	var certificate cmapi.Certificate
	err := r.Get(ctx, certificateName, &certificate)

	return &certificate, err
}

func (r *CertificateRequestReconciler) ingressFromCertificate(ctx context.Context, certificate *cmapi.Certificate) (*v1.Ingress, error) {
	var ingressName *types.NamespacedName
	for _, ref := range certificate.OwnerReferences {
		if ref.APIVersion == "networking.k8s.io/v1" && ref.Kind == "Ingress" {
			ingressName = &types.NamespacedName{
				Namespace: certificate.Namespace,
				Name:      ref.Name,
			}
		}
	}

	if ingressName == nil {
		return nil, nil
	}

	var ingress v1.Ingress
	err := r.Get(ctx, *ingressName, &ingress)
	return &ingress, err
}

func (r *CertificateRequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&cmapi.CertificateRequest{}).
		Complete(r)
}
