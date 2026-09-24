package horizon

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/evertrust/horizon-go/v2/models"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// An approver on the cluster denied a request that was already submitted: the issuer has to
// cancel it on Horizon, but only while Horizon is still waiting on it.
func TestCancelRequest(t *testing.T) {
	tests := []struct {
		name         string
		requestId    string
		response     string
		wantCancel   bool
		wantWorkflow string
		wantStatus   string
	}{
		{name: "pending enroll request is canceled", requestId: "legacy-request-id", response: enrollPendingResponse, wantCancel: true, wantWorkflow: "enroll", wantStatus: "canceled"},
		{name: "pending renew request is canceled with its own workflow", requestId: "renew-request-id", response: renewPendingResponse, wantCancel: true, wantWorkflow: "renew", wantStatus: "canceled"},
		{name: "request Horizon already denied is left alone", requestId: "legacy-request-id", response: enrollDeniedResponse},
		{name: "request never submitted is left alone"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var cancelBody map[string]string
			gets := 0
			issuer, _ := newIssuerForServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case r.Method == http.MethodGet && r.URL.Path == "/api/v1/requests/"+tc.requestId:
					gets++
					_, _ = w.Write([]byte(tc.response))
				case r.Method == http.MethodPost && r.URL.Path == "/api/v1/requests/cancel":
					body, _ := io.ReadAll(r.Body)
					_ = json.Unmarshal(body, &cancelBody)
					// Horizon answers with the request itself, now canceled.
					_, _ = w.Write([]byte(strings.Replace(tc.response, `"status":"pending"`, `"status":"canceled"`, 1)))
				default:
					http.NotFound(w, r)
				}
			}))

			certificateRequest := &cmapi.CertificateRequest{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{}}}
			if tc.requestId != "" {
				certificateRequest.Annotations[RequestIdAnnotation] = tc.requestId
			}

			if err := issuer.CancelRequest(context.Background(), certificateRequest); err != nil {
				t.Fatalf("CancelRequest() error = %v", err)
			}

			if tc.requestId == "" && gets != 0 {
				t.Errorf("Horizon was asked about a request that was never submitted")
			}
			if !tc.wantCancel {
				if cancelBody != nil {
					t.Errorf("cancel was sent to Horizon, body = %v", cancelBody)
				}
				if _, ok := certificateRequest.Annotations[RequestStatusAnnotation]; ok {
					t.Errorf("request-status annotation was written although nothing was canceled")
				}
				return
			}
			if cancelBody == nil {
				t.Fatal("expected a cancel to be sent to Horizon")
			}
			if cancelBody["_id"] != tc.requestId || cancelBody["module"] != "webra" || cancelBody["workflow"] != tc.wantWorkflow {
				t.Errorf("cancel body = %v, want id %q, module webra, workflow %q", cancelBody, tc.requestId, tc.wantWorkflow)
			}
			if got := certificateRequest.Annotations[RequestStatusAnnotation]; got != tc.wantStatus {
				t.Errorf("%s annotation = %q, want %q", RequestStatusAnnotation, got, tc.wantStatus)
			}
		})
	}
}

func TestCancelRequestReportsHorizonErrors(t *testing.T) {
	issuer, _ := newIssuerForServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(enrollPendingResponse))
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"SEC-PERM-001","title":"Insufficient privileges","status":403}`))
	}))

	certificateRequest := legacyCertificateRequest()
	err := issuer.CancelRequest(context.Background(), certificateRequest)
	if err == nil {
		t.Fatal("expected an error when Horizon refuses the cancel")
	}
	if got := certificateRequest.Annotations[RequestStatusAnnotation]; got == string(models.REQUESTSTATUS_CANCELED) {
		t.Errorf("request-status must not say canceled when Horizon refused the cancel")
	}
}
