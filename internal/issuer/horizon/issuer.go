package horizon

import (
	"context"
	"errors"
	"fmt"
	cmutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/evertrust/horizon-go"
	"github.com/evertrust/horizon-go/requests"
	"github.com/evertrust/horizon-go/rfc5280"
	"github.com/evertrust/horizon-issuer/api/v1alpha1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"time"
)

const IssuerNamespace = "horizon.evertrust.io"
const (
	RequestIdAnnotation = IssuerNamespace + "/request-id"
	OwnerAnnotation     = IssuerNamespace + "/owner"
	TeamAnnotation      = IssuerNamespace + "/team"
)

type HorizonIssuer struct {
	Client horizon.Horizon
}

// SubmitRequest is used to initially submit a decentralized enrollement request
// to an Horizon instance, from a certificate request object. It is run only once in a CSR lifecycle,
// and sets an annotation on the CertificateRequest object to ensure it is not run again.
func (r *HorizonIssuer) SubmitRequest(ctx context.Context, c client.Client, issuer v1alpha1.IssuerSpec, labels []requests.LabelElement, owner *string, team *string, certificateRequest *cmapi.CertificateRequest) (result ctrl.Result, err error) {
	logger := ctrl.LoggerFrom(ctx)

	logger.Info(fmt.Sprintf("Submitting request %s to profile %s", certificateRequest.UID, issuer.Profile))
	request, err := r.Client.Requests.DecentralizedEnroll(
		issuer.Profile,
		certificateRequest.Spec.Request,
		labels,
		owner,
		team,
	)
	if err != nil {
		return r.handleFailedRequest(certificateRequest, err)
	}

	// Update the request with the Horizon request ID
	certificateRequest.Annotations[RequestIdAnnotation] = request.Id

	cmutil.SetCertificateRequestCondition(
		certificateRequest,
		cmapi.CertificateRequestConditionReady,
		cmmeta.ConditionFalse,
		cmapi.CertificateRequestReasonPending,
		"Submitted request to Horizon",
	)

	return ctrl.Result{}, nil
}

// UpdateRequest will fetch fresh request data from Horizon, using the horizon.evertrust.io/request-id
// annotation. It will then dispatch the action to the correct handler function.
func (r *HorizonIssuer) UpdateRequest(ctx context.Context, certificateRequest *cmapi.CertificateRequest) (result ctrl.Result, err error) {
	logger := ctrl.LoggerFrom(ctx)

	request, err := r.Client.Requests.Get(certificateRequest.Annotations[RequestIdAnnotation])
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("%w: %v", errors.New("unable to fetch request from Horizon"), err)
	}

	logger.Info(fmt.Sprintf("Handling %s request %s", request.Status, certificateRequest.UID))
	switch request.Status {
	case requests.RequestStatusCompleted:
		return r.handleCompletedRequest(request, certificateRequest)
	case requests.RequestStatusPending, requests.RequestStatusApproved:
		return r.handlePendingRequest()
	case requests.RequestStatusDenied, requests.RequestStatusCanceled:
		return r.handleDeniedRequest(certificateRequest)
	}

	return ctrl.Result{}, errors.New("invalid request status " + string(request.Status))
}

func (r *HorizonIssuer) RevokeCertificate(ctx context.Context, certificateRequest *cmapi.CertificateRequest) error {
	logger := ctrl.LoggerFrom(ctx)

	logger.Info(fmt.Sprintf("Sending revocation request for request %s", certificateRequest.UID))
	_, err := r.Client.Requests.Revoke(string(certificateRequest.Status.Certificate), "UNSPECIFIED")
	return err

}

func (r *HorizonIssuer) handlePendingRequest() (result ctrl.Result, err error) {
	// We requeue the request since it still needs to be approved
	return ctrl.Result{
		Requeue:      true,
		RequeueAfter: time.Minute / 4,
	}, nil
}

func (r *HorizonIssuer) handleFailedRequest(certificateRequest *cmapi.CertificateRequest, err error) (ctrl.Result, error) {
	cmutil.SetCertificateRequestCondition(
		certificateRequest,
		cmapi.CertificateRequestConditionInvalidRequest,
		cmmeta.ConditionTrue,
		cmapi.CertificateRequestReasonFailed,
		err.Error(),
	)

	return ctrl.Result{}, err
}

func (r *HorizonIssuer) handleDeniedRequest(certificateRequest *cmapi.CertificateRequest) (result ctrl.Result, err error) {
	cmutil.SetCertificateRequestCondition(
		certificateRequest,
		cmapi.CertificateRequestConditionDenied,
		cmmeta.ConditionTrue,
		"horizon.evertrust.io",
		"Request denied on Horizon",
	)

	return ctrl.Result{}, nil
}

func (r *HorizonIssuer) handleCompletedRequest(request *requests.HorizonRequest, certificateRequest *cmapi.CertificateRequest) (result ctrl.Result, err error) {
	cmutil.SetCertificateRequestCondition(
		certificateRequest,
		cmapi.CertificateRequestConditionApproved,
		cmmeta.ConditionTrue,
		"horizon.evertrust.io",
		"Request approved on Horizon",
	)

	trustchain, err := r.Client.Rfc5280.Trustchain([]byte(request.Certificate.Certificate), rfc5280.LeafToRoot)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("%w: %v", errors.New("unable to build a trust chain for certificate"), err)
	}

	var certificate, ca string
	defer func() {
		if ca != "" {
			certificateRequest.Status.CA = []byte(ca)
		}
		if certificate != "" {
			certificateRequest.Status.Certificate = []byte(certificate)
			cmutil.SetCertificateRequestCondition(
				certificateRequest,
				cmapi.CertificateRequestConditionReady,
				cmmeta.ConditionTrue,
				cmapi.CertificateRequestReasonIssued,
				"Signed",
			)
		}
	}()
	certificate, ca = BuildPemTrustchain(trustchain)

	// We don't requeue this request since it is completed
	return ctrl.Result{}, nil
}
