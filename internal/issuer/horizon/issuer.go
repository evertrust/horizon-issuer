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
	"github.com/evertrust/horizon-go/v2/models"
	"github.com/evertrust/horizon-go/v2/utils"
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

type horizonRequest interface {
	GetId() string
	GetStatus() models.RequestStatus
	GetCertificate() models.Certificate
}

func requestFromSubmitResponse(response *models.RequestSubmit201Response) (horizonRequest, error) {
	switch {
	case response.WebRAEnrollRequestOnSubmitResponse != nil:
		return response.WebRAEnrollRequestOnSubmitResponse, nil
	case response.WebRARenewRequestOnSubmitResponse != nil:
		return response.WebRARenewRequestOnSubmitResponse, nil
	default:
		return nil, errors.New("unsupported request type returned by Horizon on submit")
	}
}

func requestFromGetResponse(response *models.RequestGet200Response) (horizonRequest, error) {
	switch {
	case response.WebRAEnrollRequestOnGetResponse != nil:
		return response.WebRAEnrollRequestOnGetResponse, nil
	case response.WebRARenewRequestOnApproveResponse != nil:
		return response.WebRARenewRequestOnApproveResponse, nil
	default:
		return nil, errors.New("unsupported request type returned by Horizon on get")
	}
}

// SubmitEnrollRequest is used to initially submit a decentralized enrollement request
// to an Horizon instance, from a certificate request object. It is run only once in a CSR lifecycle,
// and sets an annotation on the CertificateRequest object to ensure it is not run again.
func (r *HorizonIssuer) SubmitEnrollRequest(ctx context.Context, issuer v1beta1.IssuerSpec, labels []models.RequestLabelElement, owner *string, team *string, contactEmail *string, certificateRequest *cmapi.CertificateRequest) (result ctrl.Result, err error) {
	logger := ctrl.LoggerFrom(ctx)

	logger.Info(fmt.Sprintf("Submitting enrollment request %s to profile %s", certificateRequest.UID, issuer.Profile))

	templateMap := make(map[string]interface{})
	templateMap["csr"] = string(certificateRequest.Spec.Request)

	template, _, err := r.Client.RequestAPI.RequestTemplate(ctx).
		RequestTemplateRequest(models.WebRAEnrollRequestOnTemplateAsRequestTemplateRequest(&models.WebRAEnrollRequestOnTemplate{
			Module:   string(models.MODULE_WEBRA),
			Workflow: string(models.WORKFLOW_ENROLL),
			Profile:  *utils.NewNullableString(&issuer.Profile),
			Template: &templateMap,
		})).
		Execute()
	if err != nil {
		return r.handleFailedRequest(certificateRequest, err)
	}

	var req models.WebRAEnrollRequestOnSubmit
	// Fill values from the template
	req.SetWorkflow(template.WebRAEnrollRequestOnTemplateResponse.GetWorkflow())
	req.SetModule(template.WebRAEnrollRequestOnTemplateResponse.GetModule())
	req.SetProfile(template.WebRAEnrollRequestOnTemplateResponse.GetProfile())
	req.Template.SetSubject(models.TemplateIndexElementsFromResponse(template.WebRAEnrollRequestOnTemplateResponse.Template.GetSubject()))
	req.Template.SetSans(models.TemplateSansFromResponse(template.WebRAEnrollRequestOnTemplateResponse.Template.GetSans()))
	req.Template.SetExtensions(models.TemplateExtensionsFromResponse(template.WebRAEnrollRequestOnTemplateResponse.Template.GetExtensions()))
	req.Template.SetLabels(models.TemplateLabelsFromResponse(template.WebRAEnrollRequestOnTemplateResponse.Template.GetLabels()))
	req.Template.SetContactEmail(models.TemplateContactEmailFromResponse(template.WebRAEnrollRequestOnTemplateResponse.Template.GetContactEmail()))
	req.Template.SetOwner(models.TemplateOwnerFromResponse(template.WebRAEnrollRequestOnTemplateResponse.Template.GetOwner()))
	req.Template.SetTeam(models.TemplateTeamFromResponse(template.WebRAEnrollRequestOnTemplateResponse.Template.GetTeam()))
	req.Template.SetMetadata(models.TemplateMetadataFromResponse(template.WebRAEnrollRequestOnTemplateResponse.Template.GetMetadata()))
	req.Template.SetCsr(string(certificateRequest.Spec.Request))
	// Override those who are set from cert-manager
	if owner != nil {
		req.Template.Owner.Get().SetValue(*owner)
	}
	if team != nil {
		req.Template.Team.Get().SetValue(*team)
	}
	if contactEmail != nil {
		req.Template.ContactEmail.Get().SetValue(*contactEmail)
	}
	// We don't merge labels with whats returned from the template
	req.Template.SetLabels(labels)

	request, _, err := r.Client.RequestAPI.RequestSubmit(ctx).
		RequestSubmitRequest(models.WebRAEnrollRequestOnSubmitAsRequestSubmitRequest(&req)).
		Execute()

	if err != nil {
		return r.handleFailedRequest(certificateRequest, err)
	}

	// Update the request with the Horizon request ID
	submitted, err := requestFromSubmitResponse(request)
	if err != nil {
		return ctrl.Result{}, err
	}
	certificateRequest.Annotations[RequestIdAnnotation] = submitted.GetId()

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

	csr := string(certificateRequest.Spec.Request)
	request, _, err := r.Client.RequestAPI.RequestSubmit(ctx).
		RequestSubmitRequest(models.WebRARenewRequestOnSubmitAsRequestSubmitRequest(&models.WebRARenewRequestOnSubmit{
			Module:        string(models.MODULE_WEBRA),
			Workflow:      string(models.WORKFLOW_RENEW),
			CertificateId: *utils.NewNullableString(&lastCertificateId),
			Template: &models.WebRARenewRequestTemplate{
				Csr: *utils.NewNullableString(&csr),
			},
		})).
		Execute()
	if err != nil {
		return r.handleFailedRequest(certificateRequest, err)
	}

	// Update the request with the Horizon request ID
	submitted, err := requestFromSubmitResponse(request)
	if err != nil {
		return ctrl.Result{}, err
	}
	certificateRequest.Annotations[RequestIdAnnotation] = submitted.GetId()

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

	request, _, err := r.Client.RequestAPI.RequestGet(ctx, certificateRequest.Annotations[RequestIdAnnotation]).Execute()
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("%w: %v", errors.New("unable to fetch request from Horizon"), err)
	}

	fetched, err := requestFromGetResponse(request)
	if err != nil {
		return ctrl.Result{}, err
	}

	logger.Info(fmt.Sprintf("Handling %s request %s", fetched.GetStatus(), certificateRequest.UID))
	switch fetched.GetStatus() {
	case models.REQUESTSTATUS_COMPLETED:
		return r.handleCompletedRequest(fetched, certificateRequest)
	case models.REQUESTSTATUS_APPROVED:
		if challenge, ok := challengeFromRequest(request.WebRAEnrollRequestOnGetResponse); ok {
			return r.ConsumeChallenge(ctx, request.WebRAEnrollRequestOnGetResponse, challenge, certificateRequest)
		}
		return r.handlePendingRequest()
	case models.REQUESTSTATUS_PENDING:
		return r.handlePendingRequest()
	case models.REQUESTSTATUS_DENIED, models.REQUESTSTATUS_CANCELED:
		return r.handleDeniedRequest(certificateRequest)
	}

	return ctrl.Result{}, errors.New("invalid request status " + string(fetched.GetStatus()))
}

func (r *HorizonIssuer) RevokeCertificate(ctx context.Context, certificateRequest *cmapi.CertificateRequest) error {
	logger := ctrl.LoggerFrom(ctx)

	logger.Info(fmt.Sprintf("Sending revocation request for request %s", certificateRequest.UID))
	certificatePem := string(certificateRequest.Status.Certificate)
	_, _, err := r.Client.RequestAPI.RequestSubmit(ctx).
		RequestSubmitRequest(models.WebRARevokeRequestOnSubmitAsRequestSubmitRequest(&models.WebRARevokeRequestOnSubmit{
			Workflow:       string(models.WORKFLOW_REVOKE),
			CertificatePem: *utils.NewNullableString(&certificatePem),
		})).
		Execute()

	return err
}

func (r *HorizonIssuer) handlePendingRequest() (result ctrl.Result, err error) {
	// We requeue the request since it still needs to be approved
	return ctrl.Result{RequeueAfter: time.Minute / 4}, nil
}

func (r *HorizonIssuer) handleFailedRequest(certificateRequest *cmapi.CertificateRequest, err error) (ctrl.Result, error) {
	msg := formatAPIError(err)
	cmutil.SetCertificateRequestCondition(
		certificateRequest,
		cmapi.CertificateRequestConditionInvalidRequest,
		cmmeta.ConditionTrue,
		cmapi.CertificateRequestReasonFailed,
		msg,
	)

	return ctrl.Result{}, &apiError{inner: err, msg: msg}
}

type apiError struct {
	inner error
	msg   string
}

func (e *apiError) Error() string { return e.msg }
func (e *apiError) Unwrap() error { return e.inner }

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

func (r *HorizonIssuer) handleCompletedRequest(request horizonRequest, certificateRequest *cmapi.CertificateRequest) (result ctrl.Result, err error) {
	cmutil.SetCertificateRequestCondition(
		certificateRequest,
		cmapi.CertificateRequestConditionApproved,
		cmmeta.ConditionTrue,
		"horizon.evertrust.io",
		"Request approved on Horizon",
	)

	resp, _, err := r.Client.Rfc5280API.Rfc5280TcPem(context.Background(), request.GetCertificate().Certificate).Order("ltr").Execute()
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("%w: %v", errors.New("unable to build a trust chain for certificate"), err)
	}

	var certificate, ca string
	defer func() {
		if ca != "" {
			certificateRequest.Status.CA = []byte(ca)
		}
		if certificate != "" {
			issued := request.GetCertificate()
			certificateRequest.Annotations[CertificateIdAnnotation] = issued.GetId()
			certificateRequest.Annotations[OwnerAnnotation] = issued.GetOwner()
			certificateRequest.Annotations[TeamAnnotation] = issued.GetTeam()
			certificateRequest.Annotations[ContactEmailAnnotation] = issued.GetContactEmail()
			for _, label := range issued.GetLabels() {
				certificateRequest.Annotations[fmt.Sprintf("%s.%s", LabelAnnotation, label.GetKey())] = label.GetValue()
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
	certificate, ca = buildPemTrustchain(resp)

	// We don't requeue this request since it is completed
	return ctrl.Result{}, nil
}
