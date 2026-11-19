package controller

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"

	cmutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	horizonapi "github.com/evertrust/horizon-issuer/api/v1beta1"
	horizonissuer "github.com/evertrust/horizon-issuer/internal/issuer/horizon"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// The parent Certificate carries the ID of the last certificate Horizon issued for it. Without it,
// the next renewal is sent to Horizon as a new enrollment.
var _ = Describe("CertificateRequestReconciler parent certificate ID", func() {
	const certificateName = "parent-cert"

	// horizonServer counts every call made to Horizon. None is expected once a request is Ready.
	horizonServer := func() (*httptest.Server, *atomic.Int32) {
		var calls atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			http.NotFound(w, r)
		}))
		DeferCleanup(server.Close)
		return server, &calls
	}

	readyRequest := func(namespace, name, issuerName, certificateId, revision string) *cmapi.CertificateRequest {
		certificateRequest := certificateRequestForTests(namespace, name, issuerName, true)
		certificateRequest.Annotations[cmapi.CertificateNameKey] = certificateName
		certificateRequest.Annotations[cmapi.CertificateRequestRevisionAnnotationKey] = revision
		certificateRequest.Annotations[horizonissuer.RequestIdAnnotation] = "request-" + certificateId
		certificateRequest.Annotations[horizonissuer.CertificateIdAnnotation] = certificateId
		cmutil.SetCertificateRequestCondition(certificateRequest, cmapi.CertificateRequestConditionReady, cmmeta.ConditionTrue,
			cmapi.CertificateRequestReasonIssued, "Certificate issued")
		return certificateRequest
	}

	parentCertificate := func(namespace string) *cmapi.Certificate {
		return &cmapi.Certificate{
			ObjectMeta: metav1.ObjectMeta{
				Name:      certificateName,
				Namespace: namespace,
			},
			Spec: cmapi.CertificateSpec{
				SecretName: certificateName + "-tls",
				IssuerRef: cmmeta.ObjectReference{
					Group: horizonapi.GroupVersion.Group,
					Kind:  "Issuer",
				},
			},
		}
	}

	It("should set the ID on a Ready request's parent after a conflict, keeping cert-manager's changes", func() {
		const namespace = "ns-parent-a"
		server, horizonCalls := horizonServer()

		testScheme := buildTestScheme()
		issuer := readyIssuer(namespace, "issuer-a")
		issuer.Spec.URL = server.URL
		certificateRequest := readyRequest(namespace, "req-ready", "issuer-a", "cert-id-1", "1")
		certificate := parentCertificate(namespace)
		certificateKey := types.NamespacedName{Namespace: namespace, Name: certificateName}

		certificateUpdates := 0
		fakeClient := fake.NewClientBuilder().
			WithScheme(testScheme).
			WithStatusSubresource(&cmapi.CertificateRequest{}, &cmapi.Certificate{}, &horizonapi.Issuer{}).
			WithObjects(issuer, issuerSecret(namespace), certificateRequest, certificate).
			WithInterceptorFuncs(interceptor.Funcs{
				Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
					if _, ok := obj.(*cmapi.Certificate); ok {
						certificateUpdates++
						if certificateUpdates == 1 {
							// cert-manager finishes issuing revision 1 between our read and our write
							markCertificateIssued(ctx, c, certificateKey, 1)
						}
					}
					return c.Update(ctx, obj, opts...)
				},
			}).
			Build()

		reconciler := newCertificateRequestReconcilerForTests(fakeClient, testScheme, namespace)
		result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: namespace, Name: "req-ready"}})

		Expect(err).NotTo(HaveOccurred())
		Expect(result).To(Equal(ctrl.Result{}))
		Expect(certificateUpdates).To(Equal(2), "the conflicting write must be retried once")
		Expect(horizonCalls.Load()).To(BeZero(), "a Ready request must not reach Horizon")

		var updated cmapi.Certificate
		Expect(fakeClient.Get(ctx, certificateKey, &updated)).To(Succeed())
		Expect(updated.Annotations).To(HaveKeyWithValue(horizonissuer.LastCertificateIdAnnotation, "cert-id-1"))
		By("keeping what cert-manager wrote in the meantime")
		Expect(updated.Status.Revision).To(HaveValue(Equal(1)))
		Expect(cmutil.CertificateHasCondition(&updated, cmapi.CertificateCondition{
			Type:   cmapi.CertificateConditionReady,
			Status: cmmeta.ConditionTrue,
		})).To(BeTrue())

		By("leaving the Certificate alone once the ID is there")
		_, err = reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: namespace, Name: "req-ready"}})
		Expect(err).NotTo(HaveOccurred())
		Expect(certificateUpdates).To(Equal(2))
	})

	It("should not let an older Ready request overwrite the ID of a later revision", func() {
		const namespace = "ns-parent-b"
		server, horizonCalls := horizonServer()

		testScheme := buildTestScheme()
		issuer := readyIssuer(namespace, "issuer-b")
		issuer.Spec.URL = server.URL
		oldRequest := readyRequest(namespace, "req-old", "issuer-b", "cert-id-1", "1")
		certificate := parentCertificate(namespace)
		certificate.Annotations = map[string]string{horizonissuer.LastCertificateIdAnnotation: "cert-id-2"}
		certificate.Status.Revision = new(int)
		*certificate.Status.Revision = 2
		certificateKey := types.NamespacedName{Namespace: namespace, Name: certificateName}

		fakeClient := fake.NewClientBuilder().
			WithScheme(testScheme).
			WithStatusSubresource(&cmapi.CertificateRequest{}, &cmapi.Certificate{}, &horizonapi.Issuer{}).
			WithObjects(issuer, issuerSecret(namespace), oldRequest, certificate).
			Build()

		var before cmapi.Certificate
		Expect(fakeClient.Get(ctx, certificateKey, &before)).To(Succeed())

		reconciler := newCertificateRequestReconcilerForTests(fakeClient, testScheme, namespace)
		_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: namespace, Name: "req-old"}})
		Expect(err).NotTo(HaveOccurred())
		Expect(horizonCalls.Load()).To(BeZero())

		var after cmapi.Certificate
		Expect(fakeClient.Get(ctx, certificateKey, &after)).To(Succeed())
		Expect(after.Annotations).To(HaveKeyWithValue(horizonissuer.LastCertificateIdAnnotation, "cert-id-2"))
		Expect(after.ResourceVersion).To(Equal(before.ResourceVersion))
	})

	It("should return the error when the parent cannot be written, so the request is retried", func() {
		const namespace = "ns-parent-c"
		server, horizonCalls := horizonServer()

		testScheme := buildTestScheme()
		issuer := readyIssuer(namespace, "issuer-c")
		issuer.Spec.URL = server.URL
		certificateRequest := readyRequest(namespace, "req-ready", "issuer-c", "cert-id-1", "1")

		fakeClient := fake.NewClientBuilder().
			WithScheme(testScheme).
			WithStatusSubresource(&cmapi.CertificateRequest{}, &cmapi.Certificate{}, &horizonapi.Issuer{}).
			WithObjects(issuer, issuerSecret(namespace), certificateRequest, parentCertificate(namespace)).
			WithInterceptorFuncs(interceptor.Funcs{
				Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
					if _, ok := obj.(*cmapi.Certificate); ok {
						return errors.New("apiserver unavailable")
					}
					return c.Update(ctx, obj, opts...)
				},
			}).
			Build()

		reconciler := newCertificateRequestReconcilerForTests(fakeClient, testScheme, namespace)
		_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: namespace, Name: "req-ready"}})
		Expect(err).To(MatchError(ContainSubstring("apiserver unavailable")))
		Expect(horizonCalls.Load()).To(BeZero())
	})

	It("should skip a parent Certificate that no longer exists", func() {
		const namespace = "ns-parent-d"
		testScheme := buildTestScheme()
		certificateRequest := readyRequest(namespace, "req-orphan", "issuer-d", "cert-id-1", "1")

		fakeClient := fake.NewClientBuilder().
			WithScheme(testScheme).
			WithObjects(certificateRequest).
			Build()

		reconciler := newCertificateRequestReconcilerForTests(fakeClient, testScheme, namespace)
		Expect(reconciler.syncLastCertificateId(ctx, certificateRequest)).To(Succeed())
	})
})

func markCertificateIssued(ctx context.Context, c client.Client, name types.NamespacedName, revision int) {
	var latest cmapi.Certificate
	Expect(c.Get(ctx, name, &latest)).To(Succeed())
	latest.Status.Revision = &revision
	cmutil.SetCertificateCondition(&latest, latest.Generation, cmapi.CertificateConditionReady, cmmeta.ConditionTrue,
		"Ready", "Certificate is up to date and has not expired")
	Expect(c.Status().Update(ctx, &latest)).To(Succeed())
}
