package horizon

import (
	"testing"
	"time"

	cmutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/evertrust/horizon-go/v2/models"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// A request Horizon denied or canceled has to look like a failed issuance to cert-manager: Ready
// False with the Failed reason and a failure time. Ready=False/Denied alone would leave the
// parent Certificate waiting forever.
func TestHandleDeniedRequestFailsTheRequest(t *testing.T) {
	for _, status := range []models.RequestStatus{models.REQUESTSTATUS_DENIED, models.REQUESTSTATUS_CANCELED} {
		t.Run(string(status), func(t *testing.T) {
			issuer := &HorizonIssuer{}
			certificateRequest := &cmapi.CertificateRequest{}

			if _, err := issuer.handleDeniedRequest(certificateRequest, status); err != nil {
				t.Fatalf("handleDeniedRequest returned error: %v", err)
			}

			if got := certificateRequest.Annotations[RequestStatusAnnotation]; got != string(status) {
				t.Fatalf("unexpected %s annotation: got %q", RequestStatusAnnotation, got)
			}
			if certificateRequest.Status.FailureTime == nil {
				t.Fatal("expected a failure time, cert-manager uses it to back off before retrying")
			}

			ready := cmutil.GetCertificateRequestCondition(certificateRequest, cmapi.CertificateRequestConditionReady)
			if ready == nil {
				t.Fatal("expected Ready condition to be set")
			}
			if ready.Status != cmmeta.ConditionFalse {
				t.Fatalf("unexpected Ready status: got %s", ready.Status)
			}
			if ready.Reason != cmapi.CertificateRequestReasonFailed {
				t.Fatalf("unexpected Ready reason: got %s, cert-manager only fails a Certificate on %s", ready.Reason, cmapi.CertificateRequestReasonFailed)
			}
			if want := "Request " + string(status) + " on Horizon"; ready.Message != want {
				t.Fatalf("unexpected Ready message: got %q, want %q", ready.Message, want)
			}
		})
	}
}

func TestHandleDeniedRequestKeepsAnExistingFailureTime(t *testing.T) {
	issuer := &HorizonIssuer{}
	earlier := metav1.NewTime(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	certificateRequest := &cmapi.CertificateRequest{Status: cmapi.CertificateRequestStatus{FailureTime: &earlier}}

	if _, err := issuer.handleDeniedRequest(certificateRequest, models.REQUESTSTATUS_DENIED); err != nil {
		t.Fatalf("handleDeniedRequest returned error: %v", err)
	}
	if !certificateRequest.Status.FailureTime.Equal(&earlier) {
		t.Fatalf("failure time was overwritten: got %v, want %v", certificateRequest.Status.FailureTime, earlier)
	}
}
