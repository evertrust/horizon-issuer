package horizon

import (
	"context"
	"net/http"
	"strings"
	"testing"

	cmutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/evertrust/horizon-go/v2/models"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// These tests use CertificateRequests as an older issuer left them: only the request-id
// annotation, sometimes with an approval or a denial that cert-manager or the old issuer
// already recorded.
const (
	legacyRequestId = "legacy-request-id"

	enrollPendingResponse = `{"module":"webra","workflow":"enroll","_id":"legacy-request-id","holderId":"holder",
		"lastModificationDate":1,"profile":"issuer","registrationDate":1,"removeAt":1,"status":"pending","template":{}}`
	enrollDeniedResponse = `{"module":"webra","workflow":"enroll","_id":"legacy-request-id","holderId":"holder",
		"lastModificationDate":1,"profile":"issuer","registrationDate":1,"removeAt":1,"status":"denied","template":{}}`

	leafPem = "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----"
	rootPem = "-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----"
)

func trustchainResponse() string {
	cert := func(pem string, selfSigned bool) string {
		selfSignedValue := "false"
		if selfSigned {
			selfSignedValue = "true"
		}
		return `{"certificateSHAOneThumbprint":"sha1","certificateThumbprint":"sha256","dn":"CN=test","dnElements":[],
			"extendedKeyUsages":[],"isExtendedKeyUsagesCritical":false,"isKeyUsagesCritical":false,"issuerDn":"CN=ca",
			"keyType":"rsa-2048","keyUsages":[],"notAfter":1,"notBefore":1,"pem":"` + strings.ReplaceAll(pem, "\n", `\n`) + `",
			"publicKeyThumbprint":"pk","selfSigned":` + selfSignedValue + `,"signingAlgorithm":"sha256WithRSA","subjectKeyIdentifier":"ski"}`
	}
	return "[" + cert(leafPem, false) + "," + cert(rootPem, true) + "]"
}

func legacyCertificateRequest() *cmapi.CertificateRequest {
	return &cmapi.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "legacy",
			Namespace:   "default",
			Annotations: map[string]string{RequestIdAnnotation: legacyRequestId},
		},
		Spec: cmapi.CertificateRequestSpec{Request: []byte("dummy-csr")},
	}
}

func TestUpdateRequestBackfillsStatusAnnotationOnLegacyRequest(t *testing.T) {
	tests := []struct {
		name       string
		response   string
		wantStatus models.RequestStatus
		wantReq    bool
		wantDenied bool
	}{
		{name: "pending request gets the pending status", response: enrollPendingResponse, wantStatus: models.REQUESTSTATUS_PENDING, wantReq: true},
		{name: "denied request gets the denied status", response: enrollDeniedResponse, wantStatus: models.REQUESTSTATUS_DENIED, wantDenied: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			issuer, _ := newIssuerForServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/api/v1/requests/"+legacyRequestId {
					http.NotFound(w, r)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.response))
			}))

			certificateRequest := legacyCertificateRequest()
			if _, ok := certificateRequest.Annotations[RequestStatusAnnotation]; ok {
				t.Fatal("the legacy fixture must not carry the request-status annotation")
			}

			result, err := issuer.UpdateRequest(context.Background(), certificateRequest)
			if err != nil {
				t.Fatalf("UpdateRequest() error = %v", err)
			}
			if got := certificateRequest.Annotations[RequestStatusAnnotation]; got != string(tc.wantStatus) {
				t.Errorf("%s annotation = %q, want %q", RequestStatusAnnotation, got, tc.wantStatus)
			}
			if got := certificateRequest.Annotations[RequestIdAnnotation]; got != legacyRequestId {
				t.Errorf("%s annotation = %q, must be left untouched", RequestIdAnnotation, got)
			}
			if tc.wantReq && result.RequeueAfter == 0 {
				t.Errorf("expected the pending request to be requeued, got %+v", result)
			}
			if tc.wantDenied {
				ready := cmutil.GetCertificateRequestCondition(certificateRequest, cmapi.CertificateRequestConditionReady)
				if ready == nil || ready.Status != cmmeta.ConditionFalse || ready.Reason != cmapi.CertificateRequestReasonFailed {
					t.Errorf("Ready condition = %+v, want False/Failed", ready)
				}
				if certificateRequest.Status.FailureTime == nil {
					t.Error("expected a failure time on the denied request")
				}
			}
		})
	}
}

// The issuer must not touch Approved, whether nobody has decided yet or another approver
// already has. That decision belongs to the cluster's approval policies.
func TestHandleCompletedRequestLeavesApprovalToClusterPolicies(t *testing.T) {
	issued := models.NewCertificate("issued-certificate-id", leafPem, "CN=test", false, "holder", "CN=ca", "rsa-2048",
		[]models.CertificateMetadata{}, "webra", 1, 1, "pk", false, false, "01", "sha256WithRSA", []models.SubjectAlternateName{}, "sha256")
	issued.SetOwner("owner")
	issued.SetTeam("team")
	issued.SetContactEmail("owner@example.com")
	issued.SetLabels([]models.LabelData{{Key: "env", Value: "test"}})
	completed := &models.WebRAEnrollRequestOnGetResponse{
		Id:          legacyRequestId,
		Status:      models.REQUESTSTATUS_COMPLETED,
		Certificate: *models.NewNullableCertificate(issued),
	}

	tests := []struct {
		name           string
		prepare        func(*cmapi.CertificateRequest)
		wantApprovedBy string
	}{
		{
			name:    "no prior decision and nil annotations map",
			prepare: func(cr *cmapi.CertificateRequest) { cr.Annotations = nil },
		},
		{
			name: "already approved by cert-manager",
			prepare: func(cr *cmapi.CertificateRequest) {
				cmutil.SetCertificateRequestCondition(cr, cmapi.CertificateRequestConditionApproved, cmmeta.ConditionTrue, "cert-manager.io", "approved for tests")
			},
			wantApprovedBy: "cert-manager.io",
		},
		{
			name: "already denied by an approver",
			prepare: func(cr *cmapi.CertificateRequest) {
				cmutil.SetCertificateRequestCondition(cr, cmapi.CertificateRequestConditionDenied, cmmeta.ConditionTrue, "cert-manager.io", "denied for tests")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			issuer, _ := newIssuerForServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || !strings.HasPrefix(r.URL.Path, "/api/v1/rfc5280/tc/") {
					http.NotFound(w, r)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(trustchainResponse()))
			}))

			certificateRequest := legacyCertificateRequest()
			tc.prepare(certificateRequest)

			if _, err := issuer.handleCompletedRequest(completed, certificateRequest); err != nil {
				t.Fatalf("handleCompletedRequest() error = %v", err)
			}

			approved := cmutil.GetCertificateRequestCondition(certificateRequest, cmapi.CertificateRequestConditionApproved)
			switch {
			case tc.wantApprovedBy == "" && approved != nil:
				t.Errorf("Approved condition = %+v, want none: the issuer must not approve", approved)
			case tc.wantApprovedBy != "" && (approved == nil || approved.Reason != tc.wantApprovedBy):
				t.Errorf("Approved condition = %+v, want the one set by %q", approved, tc.wantApprovedBy)
			}

			ready := cmutil.GetCertificateRequestCondition(certificateRequest, cmapi.CertificateRequestConditionReady)
			if ready == nil || ready.Status != cmmeta.ConditionTrue || ready.Reason != cmapi.CertificateRequestReasonIssued {
				t.Errorf("Ready condition = %+v, want True/Issued", ready)
			}
			// buildPemTrustchain joins every certificate of the chain with a newline.
			if string(certificateRequest.Status.Certificate) != leafPem+"\n" {
				t.Errorf("Status.Certificate = %q, want the leaf", certificateRequest.Status.Certificate)
			}
			if string(certificateRequest.Status.CA) != rootPem {
				t.Errorf("Status.CA = %q, want the root", certificateRequest.Status.CA)
			}

			wantAnnotations := map[string]string{
				RequestStatusAnnotation:  string(models.REQUESTSTATUS_COMPLETED),
				CertificateIdAnnotation:  "issued-certificate-id",
				OwnerAnnotation:          "owner",
				TeamAnnotation:           "team",
				ContactEmailAnnotation:   "owner@example.com",
				LabelAnnotation + ".env": "test",
			}
			for key, want := range wantAnnotations {
				if got := certificateRequest.Annotations[key]; got != want {
					t.Errorf("%s annotation = %q, want %q", key, got, want)
				}
			}
		})
	}
}
