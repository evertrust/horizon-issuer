package horizon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	cmutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	horizon "github.com/evertrust/horizon-go/v2"
	"github.com/evertrust/horizon-go/v2/models"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/evertrust/horizon-issuer/api/v1beta1"
)

// Minimal Horizon responses carrying the required properties of each variant. horizon-go
// picks the variant from the "workflow" field, so a renew workflow must not be handled as
// an enroll one (regression for the nil pointer dereference on renewal with horizon-go >= 2.10).
const (
	renewSubmitResponse = `{"module":"webra","workflow":"renew","_id":"renew-request-id","holderId":"holder",
		"lastModificationDate":1,"profile":"issuer","registrationDate":1,"removeAt":1,"status":"pending"}`
	renewPendingResponse = `{"module":"webra","workflow":"renew","_id":"renew-request-id","holderId":"holder",
		"lastModificationDate":1,"profile":"issuer","registrationDate":1,"removeAt":1,"status":"pending"}`
	renewDeniedResponse = `{"module":"webra","workflow":"renew","_id":"renew-request-id","holderId":"holder",
		"lastModificationDate":1,"profile":"issuer","registrationDate":1,"removeAt":1,"status":"denied"}`
)

func newIssuerForServer(t *testing.T, handler http.Handler) (*HorizonIssuer, v1beta1.IssuerSpec) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	config := horizon.NewConfiguration()
	config.Servers = horizon.ServerConfigurations{{URL: server.URL}}
	config.Scheme = ""
	return &HorizonIssuer{Client: *horizon.NewAPIClient(config)}, v1beta1.IssuerSpec{URL: server.URL, Profile: "issuer"}
}

func certificateRequestForRenew() *cmapi.CertificateRequest {
	return &cmapi.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "to-renew",
			Namespace:   "default",
			Annotations: map[string]string{RequestIdAnnotation: "renew-request-id"},
		},
		Spec: cmapi.CertificateRequestSpec{Request: []byte("dummy-csr")},
	}
}

func TestSubmitRenewRequestStoresRequestId(t *testing.T) {
	issuer, spec := newIssuerForServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/requests/submit" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(renewSubmitResponse))
	}))

	certificateRequest := certificateRequestForRenew()
	delete(certificateRequest.Annotations, RequestIdAnnotation)

	if _, err := issuer.SubmitRenewRequest(context.Background(), spec, certificateRequest, "last-certificate-id"); err != nil {
		t.Fatalf("SubmitRenewRequest() error = %v", err)
	}
	if got := certificateRequest.Annotations[RequestIdAnnotation]; got != "renew-request-id" {
		t.Errorf("request-id annotation = %q, want %q", got, "renew-request-id")
	}
	ready := cmutil.GetCertificateRequestCondition(certificateRequest, cmapi.CertificateRequestConditionReady)
	if ready == nil || ready.Status != cmmeta.ConditionFalse || ready.Reason != cmapi.CertificateRequestReasonPending {
		t.Errorf("Ready condition = %+v, want False/Pending", ready)
	}
}

func TestUpdateRequestHandlesRenewWorkflow(t *testing.T) {
	tests := []struct {
		name       string
		response   string
		wantDenied bool
		wantReq    bool
	}{
		{name: "pending renew request is requeued", response: renewPendingResponse, wantReq: true},
		{name: "denied renew request is marked denied", response: renewDeniedResponse, wantDenied: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			issuer, _ := newIssuerForServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/api/v1/requests/renew-request-id" {
					http.NotFound(w, r)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.response))
			}))

			certificateRequest := certificateRequestForRenew()
			result, err := issuer.UpdateRequest(context.Background(), certificateRequest)
			if err != nil {
				t.Fatalf("UpdateRequest() error = %v", err)
			}
			if tc.wantReq && result.RequeueAfter == 0 {
				t.Errorf("expected the pending request to be requeued, got %+v", result)
			}
			if tc.wantDenied && !cmutil.CertificateRequestIsDenied(certificateRequest) {
				t.Errorf("expected the request to be denied, conditions = %+v", certificateRequest.Status.Conditions)
			}
		})
	}
}

func TestRequestFromResponsesSelectsPopulatedVariant(t *testing.T) {
	const enrollId, renewId = "enroll", "renew"
	enroll := &models.WebRAEnrollRequestOnSubmitResponse{Id: enrollId}
	renew := &models.WebRARenewRequestOnSubmitResponse{Id: renewId}

	if got, err := requestFromSubmitResponse(&models.RequestSubmit201Response{WebRAEnrollRequestOnSubmitResponse: enroll}); err != nil || got.GetId() != enrollId {
		t.Errorf("enroll submit variant: got %v, %v", got, err)
	}
	if got, err := requestFromSubmitResponse(&models.RequestSubmit201Response{WebRARenewRequestOnSubmitResponse: renew}); err != nil || got.GetId() != renewId {
		t.Errorf("renew submit variant: got %v, %v", got, err)
	}
	if _, err := requestFromSubmitResponse(&models.RequestSubmit201Response{}); err == nil {
		t.Error("expected an error when no supported submit variant is populated")
	}

	fetchedEnroll := &models.WebRAEnrollRequestOnGetResponse{Id: enrollId}
	fetchedRenew := &models.WebRARenewRequestOnApproveResponse{Id: renewId}
	if got, err := requestFromGetResponse(&models.RequestGet200Response{WebRAEnrollRequestOnGetResponse: fetchedEnroll}); err != nil || got.GetId() != enrollId {
		t.Errorf("enroll get variant: got %v, %v", got, err)
	}
	if got, err := requestFromGetResponse(&models.RequestGet200Response{WebRARenewRequestOnApproveResponse: fetchedRenew}); err != nil || got.GetId() != renewId {
		t.Errorf("renew get variant: got %v, %v", got, err)
	}
	if _, err := requestFromGetResponse(&models.RequestGet200Response{}); err == nil {
		t.Error("expected an error when no supported get variant is populated")
	}
}
