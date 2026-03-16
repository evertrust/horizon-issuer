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
	RequestStatusAnnotation     = IssuerNamespace + "/request-status"
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
		return ctrl.Result{}, err
	}

	var req models.WebRAEnrollRequestOnSubmit
	// Fill values from the template
	req.SetWorkflow(template.WebRAEnrollRequestOnTemplateResponse.GetWorkflow())
	req.SetModule(template.WebRAEnrollRequestOnTemplateResponse.GetModule())
	req.SetProfile(template.WebRAEnrollRequestOnTemplateResponse.GetProfile())
	req.Template.SetSubject(template.WebRAEnrollRequestOnTemplateResponse.Template.GetSubject())
	req.Template.SetSans(template.WebRAEnrollRequestOnTemplateResponse.Template.GetSans())
	req.Template.SetExtensions(template.WebRAEnrollRequestOnTemplateResponse.Template.GetExtensions())
	req.Template.SetLabels(template.WebRAEnrollRequestOnTemplateResponse.Template.GetLabels())
	req.Template.SetContactEmail(template.WebRAEnrollRequestOnTemplateResponse.Template.GetContactEmail())
	req.Template.SetOwner(template.WebRAEnrollRequestOnTemplateResponse.Template.GetOwner())
	req.Template.SetTeam(template.WebRAEnrollRequestOnTemplateResponse.Template.GetTeam())
	req.Template.SetMetadata(template.WebRAEnrollRequestOnTemplateResponse.Template.GetMetadata())
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

	if certificateRequest.Annotations == nil {
		certificateRequest.Annotations = make(map[string]string)
	}

	// Update the request with the Horizon request ID
	certificateRequest.Annotations[RequestIdAnnotation] = request.WebRAEnrollRequestOnSubmitResponse.Id
	certificateRequest.Annotations[RequestStatusAnnotation] = string(models.REQUESTSTATUS_PENDING)

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

	if certificateRequest.Annotations == nil {
		certificateRequest.Annotations = make(map[string]string)
	}

	// Update the request with the Horizon request ID
	certificateRequest.Annotations[RequestIdAnnotation] = request.WebRAEnrollRequestOnSubmitResponse.Id
	certificateRequest.Annotations[RequestStatusAnnotation] = string(models.REQUESTSTATUS_PENDING)

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

	logger.Info(fmt.Sprintf("Handling %s request %s", request.WebRAEnrollRequestOnApproveResponse.Status, certificateRequest.UID))
	switch request.WebRAEnrollRequestOnApproveResponse.Status {
	case models.REQUESTSTATUS_COMPLETED:
		return r.handleCompletedRequest(request.WebRAEnrollRequestOnApproveResponse, certificateRequest)
	case models.REQUESTSTATUS_PENDING, models.REQUESTSTATUS_APPROVED:
		setRequestStatusAnnotation(certificateRequest, string(request.WebRAEnrollRequestOnApproveResponse.Status))
		return r.handlePendingRequest()
	case models.REQUESTSTATUS_DENIED, models.REQUESTSTATUS_CANCELED:
		setRequestStatusAnnotation(certificateRequest, string(request.WebRAEnrollRequestOnApproveResponse.Status))
		return r.handleDeniedRequest(certificateRequest)
	}

	return ctrl.Result{}, errors.New("invalid request status " + string(request.WebRAEnrollRequestOnApproveResponse.Status))
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
	setRequestStatusAnnotation(certificateRequest, string(models.REQUESTSTATUS_DENIED))

	cmutil.SetCertificateRequestCondition(
		certificateRequest,
		cmapi.CertificateRequestConditionReady,
		cmmeta.ConditionFalse,
		cmapi.CertificateRequestReasonDenied,
		"Request denied on Horizon",
	)

	return ctrl.Result{}, nil
}

func (r *HorizonIssuer) handleCompletedRequest(request *models.WebRAEnrollRequestOnApproveResponse, certificateRequest *cmapi.CertificateRequest) (result ctrl.Result, err error) {
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
			if certificateRequest.Annotations == nil {
				certificateRequest.Annotations = make(map[string]string)
			}
			certificateRequest.Annotations[RequestStatusAnnotation] = string(models.REQUESTSTATUS_COMPLETED)
			certificateRequest.Annotations[CertificateIdAnnotation] = request.Certificate.Get().GetId()
			certificateRequest.Annotations[OwnerAnnotation] = request.Certificate.Get().GetOwner()
			certificateRequest.Annotations[TeamAnnotation] = request.Certificate.Get().GetTeam()
			certificateRequest.Annotations[ContactEmailAnnotation] = request.Certificate.Get().GetContactEmail()
			for _, label := range request.Certificate.Get().GetLabels() {
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

func setRequestStatusAnnotation(certificateRequest *cmapi.CertificateRequest, status string) {
	if certificateRequest.Annotations == nil {
		certificateRequest.Annotations = make(map[string]string)
	}
	certificateRequest.Annotations[RequestStatusAnnotation] = status
}
