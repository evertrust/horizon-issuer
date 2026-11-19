package controller

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/evertrust/horizon-go/v2/models"
	horizonapi "github.com/evertrust/horizon-issuer/api/v1beta1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// With revokeCertificates enabled, deleting a CertificateRequest revokes its certificate on
// Horizon before the finalizer is removed. Horizon refuses to revoke a certificate twice.
var _ = Describe("CertificateRequest deletion with revocation enabled", func() {
	const namespace = "ns-deletion"
	name := types.NamespacedName{Namespace: namespace, Name: "req-deleted"}

	reconcileDeletion := func(revoked bool, interceptors interceptor.Funcs) (client.Client, *revokeTracker, error) {
		certificatePem := throwawayCertificatePEM()
		tracker := &revokeTracker{}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch r.URL.Path {
			case "/api/v1/requests/submit":
				tracker.revokes++
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"TEST-ERROR","title":"Certificate is already revoked","message":"Certificate is already revoked","status":400}`))
			case "/api/v1/certificates/find":
				tracker.lookups++
				certificate := models.NewCertificate("certificate-id", certificatePem, "CN=test", false, "holder", "CN=test", "ec-256",
					[]models.CertificateMetadata{}, "webra", 0, 0, "public-key-thumbprint", revoked, true, "01", "SHA256WITHECDSA",
					[]models.SubjectAlternateName{}, "thumbprint")
				out, _ := json.Marshal(models.NewCertificateWithPermissionsResponse(*certificate, models.CertificatePermissions{}))
				_, _ = w.Write(out)
			default:
				http.NotFound(w, r)
			}
		}))
		DeferCleanup(server.Close)

		issuer := readyIssuer(namespace, "issuer-deletion")
		issuer.Spec.URL = server.URL
		issuer.Spec.RevokeCertificates = true

		certificateRequest := certificateRequestForTests(namespace, name.Name, "issuer-deletion", true)
		certificateRequest.Finalizers = []string{FinalizerName}
		certificateRequest.DeletionTimestamp = &metav1.Time{Time: time.Now()}
		certificateRequest.Status.Certificate = []byte(certificatePem)

		testScheme := buildTestScheme()
		fakeClient := fake.NewClientBuilder().
			WithScheme(testScheme).
			WithStatusSubresource(&cmapi.CertificateRequest{}, &horizonapi.Issuer{}).
			WithObjects(issuer, issuerSecret(namespace), certificateRequest).
			WithInterceptorFuncs(interceptors).
			Build()

		reconciler := newCertificateRequestReconcilerForTests(fakeClient, testScheme, namespace)
		_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: name})
		return fakeClient, tracker, err
	}

	It("removes the finalizer when Horizon already holds the certificate as revoked", func() {
		fakeClient, tracker, err := reconcileDeletion(true, interceptor.Funcs{})

		Expect(err).NotTo(HaveOccurred())
		Expect(tracker.revokes).To(Equal(1))
		Expect(tracker.lookups).To(Equal(1))

		// Without its finalizer, the object is gone.
		var updated cmapi.CertificateRequest
		err = fakeClient.Get(ctx, name, &updated)
		Expect(apierrors.IsNotFound(err)).To(BeTrue(), "expected the CertificateRequest to be deleted, got %v", err)
	})

	It("keeps the finalizer and reports the error when the certificate is not revoked", func() {
		fakeClient, _, err := reconcileDeletion(false, interceptor.Funcs{})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("Certificate is already revoked"))

		var updated cmapi.CertificateRequest
		Expect(fakeClient.Get(ctx, name, &updated)).To(Succeed())
		Expect(updated.Finalizers).To(ContainElement(FinalizerName))
	})

	It("reports a failure to remove the finalizer so that it is retried", func() {
		fakeClient, _, err := reconcileDeletion(true, interceptor.Funcs{
			Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
				return errors.New("update refused")
			},
		})

		Expect(err).To(MatchError("update refused"))

		var updated cmapi.CertificateRequest
		Expect(fakeClient.Get(ctx, name, &updated)).To(Succeed())
		Expect(updated.Finalizers).To(ContainElement(FinalizerName))
	})
})

type revokeTracker struct {
	revokes int
	lookups int
}

// throwawayCertificatePEM returns a self-signed certificate made for the test only.
func throwawayCertificatePEM() string {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).NotTo(HaveOccurred())
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "deleted.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	Expect(err).NotTo(HaveOccurred())
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
