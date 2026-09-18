package horizon

import (
	"testing"

	cmutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/evertrust/horizon-go/v2/models"
)

func TestHandleDeniedRequestStoresHorizonStatusAnnotation(t *testing.T) {
	issuer := &HorizonIssuer{}
	certificateRequest := &cmapi.CertificateRequest{}

	if _, err := issuer.handleDeniedRequest(certificateRequest); err != nil {
		t.Fatalf("handleDeniedRequest returned error: %v", err)
	}

	if got := certificateRequest.Annotations[RequestStatusAnnotation]; got != string(models.REQUESTSTATUS_DENIED) {
		t.Fatalf("unexpected %s annotation: got %q", RequestStatusAnnotation, got)
	}

	ready := cmutil.GetCertificateRequestCondition(certificateRequest, cmapi.CertificateRequestConditionReady)
	if ready == nil {
		t.Fatal("expected Ready condition to be set")
	}
	if ready.Status != cmmeta.ConditionFalse {
		t.Fatalf("unexpected Ready status: got %s", ready.Status)
	}
	if ready.Reason != cmapi.CertificateRequestReasonDenied {
		t.Fatalf("unexpected Ready reason: got %s", ready.Reason)
	}
}
