package horizon

import (
	"context"
	"errors"
	"fmt"
	"time"

	cmutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/evertrust/horizon-go/v2"
	"github.com/evertrust/horizon-issuer/api/v1beta1"
	ctrl "sigs.k8s.io/controller-runtime"
)

const IssuerNamespace = "horizon.evertrust.io"
const (
	RequestIdAnnotation         = IssuerNamespace + "/request-id"
	CertificateIdAnnotation     = IssuerNamespace + "/certificate-id"
	LastCertificateIdAnnotation = IssuerNamespace + "/last-certificate-id"
	OwnerAnnotation             = IssuerNamespace + "/owner"
	TeamAnnotation              = IssuerNamespace + "/team"
	ContactEmailAnnotation      = IssuerNamespace + "/contact-email"
	LabelAnnotation             = IssuerNamespace + "/labels"
)

type HorizonIssuer struct {
	Client horizon.APIClient
}

// SubmitEnrollRequest is used to initially submit a decentralized enrollement request
// to an Horizon instance, from a certificate request object. It is run only once in a CSR lifecycle,
// and sets an annotation on the CertificateRequest object to ensure it is not run again.
func (r *HorizonIssuer) SubmitEnrollRequest(ctx context.Context, issuer v1beta1.IssuerSpec, labels []horizon.RequestLabelElement, owner *string, team *string, contactEmail *string, certificateRequest *cmapi.CertificateRequest) (result ctrl.Result, err error) {
	logger := ctrl.LoggerFrom(ctx)

	logger.Info(fmt.Sprintf("Submitting enrollment request %s to profile %s", certificateRequest.UID, issuer.Profile))

	template, _, err := r.Client.Requests.GetEnrollTemplateWithCsr(issuer.Profile, string(certificateRequest.Spec.Request)).Execute()
	if err != nil {
		return ctrl.Result{}, err
	}

	ownerElement := &horizon.NullableString{}
	ownerElement.Set(owner)
	template.Owner = horizon.CertificateOwnerElement{Value: *ownerElement}

	teamElement := &horizon.NullableString{}
	teamElement.Set(team)
	template.Team = horizon.CertificateTeamElement{Value: *teamElement}

	contactEmailElement := &horizon.NullableString{}
	contactEmailElement.Set(contactEmail)
	template.ContactEmail = horizon.CertificateContactEmailElement{Value: *contactEmailElement}

	// We don't merge labels with whats returned from the template
	template.Labels = labels

	request, _, err := r.Client.Requests.SubmitEnroll(issuer.Profile, "", template).Execute()
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
	logger := ctrl.LoggerFrom(ctx)

	logger.Info(fmt.Sprintf("Submitting renewal request %s to profile %s", certificateRequest.UID, issuer.Profile))

	template, _, err := r.Client.Requests.GetRenewTemplateWithCertificateId(lastCertificateId).Execute()
	if err != nil {
		return ctrl.Result{}, err
	}

	template.Csr = string(certificateRequest.Spec.Request)

	request, _, err := r.Client.Requests.SubmitRenewWithCertificateId(lastCertificateId, "", template).Execute()
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
func (r *HorizonIssuer) UpdateRequest(ctx context.Context, certificateRequest *cmapi.CertificateRequest) (result ctrl.Result, err error) {
	logger := ctrl.LoggerFrom(ctx)

	request, _, err := r.Client.Requests.GetEnrollRequest(certificateRequest.Annotations[RequestIdAnnotation]).Execute()
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("%w: %v", errors.New("unable to fetch request from Horizon"), err)
	}

	logger.Info(fmt.Sprintf("Handling %s request %s", request.Status, certificateRequest.UID))
	switch request.Status {
	case horizon.REQUESTSTATUS_COMPLETED:
		return r.handleCompletedRequest(request, certificateRequest)
	case horizon.REQUESTSTATUS_PENDING, horizon.REQUESTSTATUS_APPROVED:
		return r.handlePendingRequest()
	case horizon.REQUESTSTATUS_DENIED, horizon.REQUESTSTATUS_CANCELED:
		return r.handleDeniedRequest(certificateRequest)
	}

	return ctrl.Result{}, errors.New("invalid request status " + string(request.Status))
}

func (r *HorizonIssuer) RevokeCertificate(ctx context.Context, certificateRequest *cmapi.CertificateRequest) error {
	logger := ctrl.LoggerFrom(ctx)

	logger.Info(fmt.Sprintf("Sending revocation request for request %s", certificateRequest.UID))
	_, _, err := r.Client.Requests.SubmitRevokeWithCertificatePem(
		string(certificateRequest.Status.Certificate),
		&horizon.WebraRevokeTemplate{
			RevocationReason: "UNSPECIFIED",
		},
	).Execute()

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

func (r *HorizonIssuer) handleCompletedRequest(request *horizon.WebRAEnrollResponse, certificateRequest *cmapi.CertificateRequest) (result ctrl.Result, err error) {
	cmutil.SetCertificateRequestCondition(
		certificateRequest,
		cmapi.CertificateRequestConditionApproved,
		cmmeta.ConditionTrue,
		"horizon.evertrust.io",
		"Request approved on Horizon",
	)

	resp, _, err := r.Client.Rfc5280API.Rfc5280TcPem(context.Background(), request.Certificate.Certificate).Order("ltr").Execute()
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("%w: %v", errors.New("unable to build a trust chain for certificate"), err)
	}

	var certificate, ca string
	defer func() {
		if ca != "" {
			certificateRequest.Status.CA = []byte(ca)
		}
		if certificate != "" {
			certificateRequest.Annotations[CertificateIdAnnotation] = request.Certificate.Id
			certificateRequest.Annotations[OwnerAnnotation] = request.Certificate.GetOwner()
			certificateRequest.Annotations[TeamAnnotation] = request.Certificate.GetTeam()
			certificateRequest.Annotations[ContactEmailAnnotation] = request.Certificate.GetContactEmail()
			for _, label := range request.Certificate.Labels {
				certificateRequest.Annotations[fmt.Sprintf("%s.%s", LabelAnnotation, label.Key)] = label.Value
			}

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
	certificate, ca = BuildPemTrustchain(resp)

	// We don't requeue this request since it is completed
	return ctrl.Result{}, nil
}
