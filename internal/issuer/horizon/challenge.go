package horizon

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"net/http"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
	"github.com/evertrust/horizon-go/v2"
	"github.com/evertrust/horizon-go/v2/models"
	ctrl "sigs.k8s.io/controller-runtime"
)

// dnElementTypes maps the attribute types of a CSR subject
// to the DN element types understood by Horizon.
var dnElementTypes = map[string]string{
	"2.5.4.3":                    "cn",
	"2.5.4.4":                    "surname",
	"2.5.4.5":                    "serialNumber",
	"2.5.4.6":                    "c",
	"2.5.4.7":                    "l",
	"2.5.4.8":                    "st",
	"2.5.4.9":                    "street",
	"2.5.4.10":                   "o",
	"2.5.4.11":                   "ou",
	"2.5.4.12":                   "t",
	"2.5.4.13":                   "description",
	"2.5.4.42":                   "givenName",
	"2.5.4.45":                   "uniqueIdentifier",
	"2.5.4.97":                   "organizationIdentifier",
	"0.9.2342.19200300.100.1.1":  "uid",
	"0.9.2342.19200300.100.1.25": "dc",
	"1.2.840.113549.1.9.1":       "e",
	"1.2.840.113549.1.9.2":       "unstructuredName",
	"1.2.840.113549.1.9.8":       "unstructuredAddress",
}

func challengeFromRequest(request *models.WebRAEnrollRequestOnGetResponse) (string, bool) {
	if request == nil || request.GetWorkflow() != string(models.WORKFLOW_ENROLL) || request.Status != models.REQUESTSTATUS_APPROVED {
		return "", false
	}
	password := request.Password.Get()
	if password == nil {
		return "", false
	}
	challenge := password.Value.Get()
	if challenge == nil || *challenge == "" {
		return "", false
	}
	return *challenge, true
}

func (r *HorizonIssuer) ConsumeChallenge(ctx context.Context, request *models.WebRAEnrollRequestOnGetResponse, challenge string, certificateRequest *cmapi.CertificateRequest) (result ctrl.Result, err error) {
	logger := ctrl.LoggerFrom(ctx)

	logger.Info(fmt.Sprintf("Consuming challenge of request %s on profile %s", certificateRequest.UID, request.GetProfile()))

	template := models.NewWebRAChallengeSubmitRequestTemplate()
	template.SetCsr(string(certificateRequest.Spec.Request))

	if !requestDefinesIdentity(request) {
		csr, err := pki.DecodeX509CertificateRequestBytes(certificateRequest.Spec.Request)
		if err != nil {
			return r.handleFailedRequest(certificateRequest, err)
		}
		if subject := subjectFromCSR(csr); len(subject) > 0 {
			template.SetSubject(subject)
		}
		if sans := sansFromCSR(csr); len(sans) > 0 {
			template.SetSans(sans)
		}
	}

	_, _, err = r.Client.ChallengeAPI.ChallengeSubmit(ctx).
		WebRAChallengeSubmitRequest(*models.NewWebRAChallengeSubmitRequest(challenge, request.GetProfile(), *template)).
		Execute()
	if err != nil {
		var apiErr *horizon.GenericOpenAPIError
		if errors.As(err, &apiErr) && apiErr.StatusCode() >= http.StatusBadRequest && apiErr.StatusCode() < http.StatusInternalServerError {
			return r.handleFailedRequest(certificateRequest, err)
		}
		return ctrl.Result{}, fmt.Errorf("unable to consume challenge: %s", formatAPIError(err))
	}

	completed, _, err := r.Client.RequestAPI.RequestGet(ctx, request.Id).Execute()
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("%w: %v", errors.New("unable to fetch request from Horizon"), err)
	}
	fetched, err := requestFromGetResponse(completed)
	if err != nil {
		return ctrl.Result{}, err
	}
	if fetched.GetStatus() != models.REQUESTSTATUS_COMPLETED {
		return r.handlePendingRequest()
	}

	return r.handleCompletedRequest(fetched, certificateRequest)
}
func requestDefinesIdentity(request *models.WebRAEnrollRequestOnGetResponse) bool {
	return len(request.Template.GetSubject()) > 0 ||
		len(request.Template.GetSans()) > 0 ||
		len(request.Template.GetExtensions()) > 0
}

func subjectFromCSR(csr *x509.CertificateRequest) []models.IndexedDNElement {
	var rdns pkix.RDNSequence
	if _, err := asn1.Unmarshal(csr.RawSubject, &rdns); err != nil {
		rdns = csr.Subject.ToRDNSequence()
	}

	subject := make([]models.IndexedDNElement, 0)
	indexes := make(map[string]int)
	for _, rdn := range rdns {
		for _, attribute := range rdn {
			elementType, ok := dnElementTypes[attribute.Type.String()]
			if !ok {
				continue
			}
			value, ok := attribute.Value.(string)
			if !ok || value == "" {
				continue
			}
			indexes[elementType]++
			element := models.NewIndexedDNElement(fmt.Sprintf("%s.%d", elementType, indexes[elementType]))
			element.SetValue(value)
			subject = append(subject, *element)
		}
	}
	return subject
}

func sansFromCSR(csr *x509.CertificateRequest) []models.ListSANElement {
	ips := make([]string, 0, len(csr.IPAddresses))
	for _, ip := range csr.IPAddresses {
		ips = append(ips, ip.String())
	}
	uris := make([]string, 0, len(csr.URIs))
	for _, uri := range csr.URIs {
		uris = append(uris, uri.String())
	}

	sans := make([]models.ListSANElement, 0)
	for _, san := range []struct {
		sanType string
		values  []string
	}{
		{"DNSNAME", csr.DNSNames},
		{"RFC822NAME", csr.EmailAddresses},
		{"IPADDRESS", ips},
		{"URI", uris},
	} {
		if len(san.values) == 0 {
			continue
		}
		element := models.NewListSANElementWithDefaults()
		element.SetType(san.sanType)
		element.SetValue(san.values)
		sans = append(sans, *element)
	}
	return sans
}
