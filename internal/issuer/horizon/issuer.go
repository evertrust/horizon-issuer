package horizon

import (
	"context"
	"errors"
	"fmt"
	cmutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/evertrust/horizon-go"
	"github.com/evertrust/horizon-go/client"
	"github.com/evertrust/horizon-go/rfc5280"
	"github.com/evertrust/horizon-issuer/api/v1beta1"
	"github.com/go-logr/logr"
	ctrl "sigs.k8s.io/controller-runtime"
	"time"
)

const IssuerNamespace = "horizon.evertrust.io"
const (
	RequestIdAnnotation         = IssuerNamespace + "/request-id"
	CertificateIdAnnotation     = IssuerNamespace + "/certificate-id"
	LastCertificateIdAnnotation = IssuerNamespace + "/last-certificate-id"
	OwnerAnnotation             = IssuerNamespace + "/owner"
	TeamAnnotation              = IssuerNamespace + "/team"
	ContactEmailAnnotation      = IssuerNamespace + "/contact-email"
)

type HorizonIssuer struct {
	Client client.Client
	Log    logr.Logger
}

// SubmitEnrollRequest is used to initially submit a decentralized enrollement request
// to an Horizon instance, from a certificate request object. It is run only once in a CSR lifecycle,
// and sets an annotation on the CertificateRequest object to ensure it is not run again.
func (r *HorizonIssuer) SubmitEnrollRequest(issuer v1beta1.IssuerSpec, labels []horizon.LabelElement, owner *string, team *string, contactEmail *string, certificateRequest *cmapi.CertificateRequest) (result ctrl.Result, err error) {
	r.Log.Info(fmt.Sprintf("Submitting enrollment request %s to profile %s", certificateRequest.UID, issuer.Profile))
	template, err := r.Client.Requests.GetEnrollTemplate(horizon.WebRAEnrollTemplateParams{
		Csr:     string(certificateRequest.Spec.Request),
		Profile: issuer.Profile,
	})
	if err != nil {
		return r.handleFailedRequest(certificateRequest, err)
	}

	template.Labels = labels
	if owner != nil {
		template.Owner = &horizon.OwnerElement{Value: &horizon.String{String: *owner}}
	}
	if team != nil {
		template.Team = &horizon.TeamElement{Value: &horizon.String{String: *team}}
	}
	if contactEmail != nil {
		template.ContactEmail = &horizon.ContactEmailElement{Value: &horizon.String{String: *contactEmail}}
	}

	request, err := r.Client.Requests.NewEnrollRequest(horizon.WebRAEnrollRequestParams{
		Profile:  issuer.Profile,
		Template: template,
	})

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
		"Submitted enrollment request to Horizon",
	)

	return ctrl.Result{}, nil
}

func (r *HorizonIssuer) SubmitRenewRequest(ctx context.Context, issuer v1beta1.IssuerSpec, certificateRequest *cmapi.CertificateRequest, lastCertificateId string) (result ctrl.Result, err error) {
	r.Log.Info(fmt.Sprintf("Submitting renewal request %s to profile %s", certificateRequest.UID, issuer.Profile))
	request, err := r.Client.Requests.NewRenewRequest(horizon.WebRARenewRequestParams{CertToRenewId: lastCertificateId, Template: &horizon.WebRARenewTemplate{Csr: string(certificateRequest.Spec.Request)}})
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
		"Submitted renewal request to Horizon",
	)

	return ctrl.Result{}, nil
}

// UpdateRequest will fetch fresh request data from Horizon, using the horizon.evertrust.io/request-id
// annotation. It will then dispatch the action to the correct handler function.
func (r *HorizonIssuer) UpdateRequest(certificateRequest *cmapi.CertificateRequest) (result ctrl.Result, err error) {
	request, err := r.Client.Requests.GetEnrollRequest(certificateRequest.Annotations[RequestIdAnnotation])
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("%w: %v", errors.New("unable to fetch request from Horizon"), err)
	}

	r.Log.Info(fmt.Sprintf("Handling %s request %s", request.Status, certificateRequest.UID))
	switch request.Status {
	case horizon.Completed:
		return r.handleCompletedRequest(request, certificateRequest)
	case horizon.Pending, horizon.Approved:
		return r.handlePendingRequest()
	case horizon.Denied, horizon.Canceled:
		return r.handleDeniedRequest(certificateRequest)
	}

	return ctrl.Result{}, errors.New("invalid request status " + string(request.Status))
}

func (r *HorizonIssuer) RevokeCertificate(certificateRequest *cmapi.CertificateRequest) error {
	r.Log.Info(fmt.Sprintf("Sending revocation request for request %s", certificateRequest.UID))
	_, err := r.Client.Requests.NewRevokeRequest(horizon.WebRARevokeRequestParams{CertificatePEM: string(certificateRequest.Status.Certificate), RevocationReason: "UNSPECIFIED"})
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

func (r *HorizonIssuer) handleCompletedRequest(request *horizon.WebRAEnrollRequest, certificateRequest *cmapi.CertificateRequest) (result ctrl.Result, err error) {
	cmutil.SetCertificateRequestCondition(
		certificateRequest,
		cmapi.CertificateRequestConditionApproved,
		cmmeta.ConditionTrue,
		"horizon.evertrust.io",
		"Request approved on Horizon",
	)

	trustchain, err := r.Client.Rfc5280.Trustchain([]byte(request.Certificate.Certificate), rfc5280.LeafToRoot)
	if err != nil {
		trustchain = []rfc5280.CfCertificate{{Pem: request.Certificate.Certificate}}
		r.Log.Error(err, "unable to build a trust chain for certificate")
	}

	var certificate, ca string
	defer func() {
		if ca != "" {
			certificateRequest.Status.CA = []byte(ca)
		}
		if certificate != "" {
			certificateRequest.Annotations[CertificateIdAnnotation] = request.Certificate.Id
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
