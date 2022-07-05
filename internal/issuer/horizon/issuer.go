package horizon

import (
	"context"
	"errors"
	"fmt"
	"github.com/evertrust/horizon-go"
	"github.com/evertrust/horizon-go/requests"
	cmutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"time"
)

const IssuerNamespace = "horizon.evertrust.io"
const RequestIdAnnotation = IssuerNamespace + "/request-id"

type HorizonIssuer struct {
	Client horizon.Horizon
}

func (r *HorizonIssuer) SubmitRequest(ctx context.Context, client client.Client, profile string, certificateRequest *cmapi.CertificateRequest) (result ctrl.Result, err error) {
	logger := log.FromContext(ctx)

	logger.Info(fmt.Sprintf("Submitting request %s to profile %s", certificateRequest.UID, profile))
	request, err := r.Client.Requests.DecentralizedEnroll(
		profile,
		certificateRequest.Spec.Request,
		[]requests.LabelElement{},
		nil,
		nil,
	)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("%w: %v", errors.New("unable to sign the CSR using Horizon"), err)
	}

	// Update the request with the Horizon request ID
	certificateRequest.Annotations[RequestIdAnnotation] = request.Id
	if err := client.Update(ctx, certificateRequest); err != nil {
		return ctrl.Result{}, fmt.Errorf("%w: %v", errors.New("unable to update the cert request"), err)
	}

	cmutil.SetCertificateRequestCondition(
		certificateRequest,
		cmapi.CertificateRequestConditionReady,
		cmmeta.ConditionFalse,
		cmapi.CertificateRequestReasonPending,
		"Submitted request to Horizon",
	)

	return ctrl.Result{
		Requeue:      true,
		RequeueAfter: time.Minute,
	}, nil
}

func (r *HorizonIssuer) UpdateRequest(ctx context.Context, certificateRequest *cmapi.CertificateRequest) (result ctrl.Result, err error) {
	logger := log.FromContext(ctx)

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
	logger := log.FromContext(ctx)

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

	certificateRequest.Status.Certificate = []byte(request.Certificate.Certificate)

	cmutil.SetCertificateRequestCondition(
		certificateRequest,
		cmapi.CertificateRequestConditionReady,
		cmmeta.ConditionTrue,
		cmapi.CertificateRequestReasonIssued,
		"Signed",
	)

	// We don't requeue this request since it is completed
	return ctrl.Result{}, nil
}
