package controller

import (
	"net/http"
	"net/http/httptest"

	cmutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	horizonapi "github.com/evertrust/horizon-issuer/api/v1beta1"
	horizonissuer "github.com/evertrust/horizon-issuer/internal/issuer/horizon"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// An older issuer left its requests with the request-id annotation and nothing else, and it
// marked a refusal with a Denied condition rather than Ready=False/Denied. The controller has
// to pick those requests up after an upgrade.
var _ = Describe("CertificateRequestReconciler backward compatibility", func() {
	const legacyRequestId = "legacy-request-id"

	It("should keep tracking a request that only carries the request-id annotation", func() {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.Path != "/api/v1/requests/"+legacyRequestId {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"module":"webra","workflow":"enroll","_id":"` + legacyRequestId + `","holderId":"holder",
				"lastModificationDate":1,"profile":"default","registrationDate":1,"removeAt":1,"status":"pending","template":{}}`))
		}))
		DeferCleanup(server.Close)

		testScheme := buildTestScheme()
		issuer := readyIssuer("ns-compat-a", "issuer-a")
		issuer.Spec.URL = server.URL
		secret := issuerSecret("ns-compat-a")
		certificateRequest := certificateRequestForTests("ns-compat-a", "req-legacy", "issuer-a", true)
		certificateRequest.Annotations[horizonissuer.RequestIdAnnotation] = legacyRequestId
		name := types.NamespacedName{Namespace: "ns-compat-a", Name: "req-legacy"}

		fakeClient := fake.NewClientBuilder().
			WithScheme(testScheme).
			WithStatusSubresource(&cmapi.CertificateRequest{}, &horizonapi.Issuer{}).
			WithObjects(issuer, secret, certificateRequest).
			Build()

		reconciler := newCertificateRequestReconcilerForTests(fakeClient, testScheme, "ns-compat-a")
		result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: name})

		Expect(err).NotTo(HaveOccurred())
		Expect(result.RequeueAfter).To(BeNumerically(">", 0))

		var updated cmapi.CertificateRequest
		Expect(fakeClient.Get(ctx, name, &updated)).To(Succeed())
		Expect(updated.Annotations[horizonissuer.RequestIdAnnotation]).To(Equal(legacyRequestId))
		Expect(updated.Annotations[horizonissuer.RequestStatusAnnotation]).To(Equal("pending"))
	})

	It("should fail a request Horizon denied the way cert-manager expects, then leave it alone", func() {
		requests := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.Path != "/api/v1/requests/"+legacyRequestId {
				http.NotFound(w, r)
				return
			}
			requests++
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"module":"webra","workflow":"enroll","_id":"` + legacyRequestId + `","holderId":"holder",
				"lastModificationDate":1,"profile":"default","registrationDate":1,"removeAt":1,"status":"denied","template":{}}`))
		}))
		DeferCleanup(server.Close)

		testScheme := buildTestScheme()
		issuer := readyIssuer("ns-compat-d", "issuer-d")
		issuer.Spec.URL = server.URL
		secret := issuerSecret("ns-compat-d")
		certificateRequest := certificateRequestForTests("ns-compat-d", "req-horizon-denied", "issuer-d", false)
		certificateRequest.Annotations[horizonissuer.RequestIdAnnotation] = legacyRequestId
		name := types.NamespacedName{Namespace: "ns-compat-d", Name: "req-horizon-denied"}

		fakeClient := fake.NewClientBuilder().
			WithScheme(testScheme).
			WithStatusSubresource(&cmapi.CertificateRequest{}, &horizonapi.Issuer{}).
			WithObjects(issuer, secret, certificateRequest).
			Build()

		reconciler := newCertificateRequestReconcilerForTests(fakeClient, testScheme, "ns-compat-d")
		result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: name})
		Expect(err).NotTo(HaveOccurred())
		Expect(result).To(Equal(ctrl.Result{}))
		Expect(requests).To(Equal(1))

		var failed cmapi.CertificateRequest
		Expect(fakeClient.Get(ctx, name, &failed)).To(Succeed())
		By("giving cert-manager the two signals it fails a Certificate on: Ready=False/Failed and a failure time")
		ready := cmutil.GetCertificateRequestCondition(&failed, cmapi.CertificateRequestConditionReady)
		Expect(ready).NotTo(BeNil())
		Expect(ready.Status).To(Equal(cmmeta.ConditionFalse))
		Expect(ready.Reason).To(Equal(cmapi.CertificateRequestReasonFailed))
		Expect(ready.Message).To(Equal("Request denied on Horizon"))
		Expect(failed.Status.FailureTime).NotTo(BeNil())
		Expect(failed.Annotations[horizonissuer.RequestStatusAnnotation]).To(Equal("denied"))
		By("not touching the approval conditions")
		Expect(cmutil.GetCertificateRequestCondition(&failed, cmapi.CertificateRequestConditionApproved)).To(BeNil())
		Expect(cmutil.CertificateRequestIsDenied(&failed)).To(BeFalse())

		By("ignoring the failed request on the next reconcile")
		result, err = reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: name})
		Expect(err).NotTo(HaveOccurred())
		Expect(result).To(Equal(ctrl.Result{}))
		Expect(requests).To(Equal(1), "Horizon must not be asked again")
		var after cmapi.CertificateRequest
		Expect(fakeClient.Get(ctx, name, &after)).To(Succeed())
		Expect(after.ResourceVersion).To(Equal(failed.ResourceVersion))
	})

	It("should turn a Denied condition set by a previous issuer version into Ready=False/Denied", func() {
		// The previous version set Denied when Horizon itself denied the request, so there is
		// nothing left to cancel on Horizon.
		cancels := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch {
			case r.Method == http.MethodGet && r.URL.Path == "/api/v1/requests/"+legacyRequestId:
				_, _ = w.Write([]byte(`{"module":"webra","workflow":"enroll","_id":"` + legacyRequestId + `","holderId":"holder",
					"lastModificationDate":1,"profile":"default","registrationDate":1,"removeAt":1,"status":"denied","template":{}}`))
			case r.Method == http.MethodPost && r.URL.Path == "/api/v1/requests/cancel":
				cancels++
				_, _ = w.Write([]byte(`{"module":"webra","workflow":"enroll","_id":"` + legacyRequestId + `","holderId":"holder",
					"lastModificationDate":1,"profile":"default","registrationDate":1,"removeAt":1,"status":"canceled","template":{}}`))
			default:
				http.NotFound(w, r)
			}
		}))
		DeferCleanup(server.Close)

		testScheme := buildTestScheme()
		issuer := readyIssuer("ns-compat-b", "issuer-b")
		issuer.Spec.URL = server.URL
		secret := issuerSecret("ns-compat-b")
		certificateRequest := certificateRequestForTests("ns-compat-b", "req-old-denied", "issuer-b", false)
		certificateRequest.Annotations[horizonissuer.RequestIdAnnotation] = legacyRequestId
		cmutil.SetCertificateRequestCondition(certificateRequest, cmapi.CertificateRequestConditionDenied, cmmeta.ConditionTrue,
			"horizon.evertrust.io", "Request denied on Horizon")
		name := types.NamespacedName{Namespace: "ns-compat-b", Name: "req-old-denied"}

		fakeClient := fake.NewClientBuilder().
			WithScheme(testScheme).
			WithStatusSubresource(&cmapi.CertificateRequest{}, &horizonapi.Issuer{}).
			WithObjects(issuer, secret, certificateRequest).
			Build()

		reconciler := newCertificateRequestReconcilerForTests(fakeClient, testScheme, "ns-compat-b")
		result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: name})

		Expect(err).NotTo(HaveOccurred())
		Expect(result).To(Equal(ctrl.Result{}))

		var updated cmapi.CertificateRequest
		Expect(fakeClient.Get(ctx, name, &updated)).To(Succeed())
		ready := cmutil.GetCertificateRequestCondition(&updated, cmapi.CertificateRequestConditionReady)
		Expect(ready).NotTo(BeNil())
		Expect(ready.Status).To(Equal(cmmeta.ConditionFalse))
		Expect(ready.Reason).To(Equal(cmapi.CertificateRequestReasonDenied))
		Expect(updated.Status.FailureTime).NotTo(BeNil())
		Expect(cmutil.CertificateRequestIsDenied(&updated)).To(BeTrue(), "the original Denied condition must be kept")
		Expect(updated.Annotations[horizonissuer.RequestIdAnnotation]).To(Equal(legacyRequestId))
		Expect(cancels).To(Equal(0), "a request Horizon already denied must not be canceled")
	})

	It("should cancel the Horizon request when an approver denies a request still pending there", func() {
		cancels := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch {
			case r.Method == http.MethodGet && r.URL.Path == "/api/v1/requests/"+legacyRequestId:
				status := "pending"
				if cancels > 0 {
					status = "canceled"
				}
				_, _ = w.Write([]byte(`{"module":"webra","workflow":"enroll","_id":"` + legacyRequestId + `","holderId":"holder",
					"lastModificationDate":1,"profile":"default","registrationDate":1,"removeAt":1,"status":"` + status + `","template":{}}`))
			case r.Method == http.MethodPost && r.URL.Path == "/api/v1/requests/cancel":
				cancels++
				_, _ = w.Write([]byte(`{"module":"webra","workflow":"enroll","_id":"` + legacyRequestId + `","holderId":"holder",
					"lastModificationDate":1,"profile":"default","registrationDate":1,"removeAt":1,"status":"canceled","template":{}}`))
			default:
				http.NotFound(w, r)
			}
		}))
		DeferCleanup(server.Close)

		testScheme := buildTestScheme()
		issuer := readyIssuer("ns-compat-e", "issuer-e")
		issuer.Spec.URL = server.URL
		secret := issuerSecret("ns-compat-e")
		certificateRequest := certificateRequestForTests("ns-compat-e", "req-denied-on-cluster", "issuer-e", false)
		certificateRequest.Annotations[horizonissuer.RequestIdAnnotation] = legacyRequestId
		certificateRequest.Annotations[horizonissuer.RequestStatusAnnotation] = "pending"
		cmutil.SetCertificateRequestCondition(certificateRequest, cmapi.CertificateRequestConditionDenied, cmmeta.ConditionTrue,
			"policy.cert-manager.io", "denied by an approver on the cluster")
		name := types.NamespacedName{Namespace: "ns-compat-e", Name: "req-denied-on-cluster"}

		fakeClient := fake.NewClientBuilder().
			WithScheme(testScheme).
			WithStatusSubresource(&cmapi.CertificateRequest{}, &horizonapi.Issuer{}).
			WithObjects(issuer, secret, certificateRequest).
			Build()

		reconciler := newCertificateRequestReconcilerForTests(fakeClient, testScheme, "ns-compat-e")
		result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: name})
		Expect(err).NotTo(HaveOccurred())
		Expect(result).To(Equal(ctrl.Result{}))
		Expect(cancels).To(Equal(1))

		var updated cmapi.CertificateRequest
		Expect(fakeClient.Get(ctx, name, &updated)).To(Succeed())
		ready := cmutil.GetCertificateRequestCondition(&updated, cmapi.CertificateRequestConditionReady)
		Expect(ready).NotTo(BeNil())
		Expect(ready.Status).To(Equal(cmmeta.ConditionFalse))
		Expect(ready.Reason).To(Equal(cmapi.CertificateRequestReasonDenied))
		Expect(updated.Status.FailureTime).NotTo(BeNil())
		Expect(updated.Annotations[horizonissuer.RequestStatusAnnotation]).To(Equal("canceled"))

		By("not canceling again once the request is closed")
		_, err = reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: name})
		Expect(err).NotTo(HaveOccurred())
		Expect(cancels).To(Equal(1))
	})

	It("should retry the cancel instead of closing a denied request when Horizon is unreachable", func() {
		testScheme := buildTestScheme()
		issuer := readyIssuer("ns-compat-f", "issuer-f")
		issuer.Spec.URL = "http://127.0.0.1:1"
		secret := issuerSecret("ns-compat-f")
		certificateRequest := certificateRequestForTests("ns-compat-f", "req-denied-unreachable", "issuer-f", false)
		certificateRequest.Annotations[horizonissuer.RequestIdAnnotation] = legacyRequestId
		cmutil.SetCertificateRequestCondition(certificateRequest, cmapi.CertificateRequestConditionDenied, cmmeta.ConditionTrue,
			"policy.cert-manager.io", "denied by an approver on the cluster")
		name := types.NamespacedName{Namespace: "ns-compat-f", Name: "req-denied-unreachable"}

		fakeClient := fake.NewClientBuilder().
			WithScheme(testScheme).
			WithStatusSubresource(&cmapi.CertificateRequest{}, &horizonapi.Issuer{}).
			WithObjects(issuer, secret, certificateRequest).
			Build()

		reconciler := newCertificateRequestReconcilerForTests(fakeClient, testScheme, "ns-compat-f")
		_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: name})
		Expect(err).To(HaveOccurred())

		var updated cmapi.CertificateRequest
		Expect(fakeClient.Get(ctx, name, &updated)).To(Succeed())
		ready := cmutil.GetCertificateRequestCondition(&updated, cmapi.CertificateRequestConditionReady)
		Expect(ready).NotTo(BeNil())
		Expect(ready.Reason).NotTo(Equal(cmapi.CertificateRequestReasonDenied), "the request must stay open until the cancel went through")
	})

	It("should leave a request already marked Ready=False/Denied untouched", func() {
		testScheme := buildTestScheme()
		issuer := readyIssuer("ns-compat-c", "issuer-c")
		secret := issuerSecret("ns-compat-c")
		certificateRequest := certificateRequestForTests("ns-compat-c", "req-denied", "issuer-c", false)
		certificateRequest.Annotations[horizonissuer.RequestIdAnnotation] = legacyRequestId
		cmutil.SetCertificateRequestCondition(certificateRequest, cmapi.CertificateRequestConditionReady, cmmeta.ConditionFalse,
			cmapi.CertificateRequestReasonDenied, "Request denied on Horizon")
		name := types.NamespacedName{Namespace: "ns-compat-c", Name: "req-denied"}

		fakeClient := fake.NewClientBuilder().
			WithScheme(testScheme).
			WithStatusSubresource(&cmapi.CertificateRequest{}, &horizonapi.Issuer{}).
			WithObjects(issuer, secret, certificateRequest).
			Build()

		var before cmapi.CertificateRequest
		Expect(fakeClient.Get(ctx, name, &before)).To(Succeed())

		reconciler := newCertificateRequestReconcilerForTests(fakeClient, testScheme, "ns-compat-c")
		result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: name})

		Expect(err).NotTo(HaveOccurred())
		Expect(result).To(Equal(ctrl.Result{}))

		var after cmapi.CertificateRequest
		Expect(fakeClient.Get(ctx, name, &after)).To(Succeed())
		Expect(after.ResourceVersion).To(Equal(before.ResourceVersion))
		Expect(after.Status.FailureTime).To(BeNil())
	})
})
