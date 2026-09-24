package controller

import (
	"context"
	"errors"

	cmutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	horizonapi "github.com/evertrust/horizon-issuer/api/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("CertificateRequestReconciler", func() {
	It("should process approved requests without request-id through submit path", func() {
		testScheme := buildTestScheme()
		issuer := readyIssuer("ns-a", "issuer-a")
		secret := issuerSecret("ns-a")
		certificateRequest := certificateRequestForTests("ns-a", "req-approved", "issuer-a", true)

		fakeClient := fake.NewClientBuilder().
			WithScheme(testScheme).
			WithStatusSubresource(&cmapi.CertificateRequest{}, &horizonapi.Issuer{}).
			WithObjects(issuer, secret, certificateRequest).
			Build()

		reconciler := newCertificateRequestReconcilerForTests(fakeClient, testScheme, "ns-a")
		result, err := reconciler.Reconcile(ctx, ctrl.Request{
			NamespacedName: types.NamespacedName{
				Namespace: "ns-a",
				Name:      "req-approved",
			},
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("certificates.cert-manager.io \"missing-cert\" not found"))
		Expect(result).To(Equal(ctrl.Result{}))

		var updated cmapi.CertificateRequest
		Expect(fakeClient.Get(ctx, types.NamespacedName{Namespace: "ns-a", Name: "req-approved"}, &updated)).To(Succeed())

		ready := cmutil.GetCertificateRequestCondition(&updated, cmapi.CertificateRequestConditionReady)
		Expect(ready).NotTo(BeNil())
		Expect(ready.Status).To(Equal(cmmeta.ConditionFalse))
		Expect(ready.Reason).To(Equal(cmapi.CertificateRequestReasonPending))
		Expect(updated.Annotations["horizon.evertrust.io/request-id"]).To(BeEmpty())
	})

	It("should process unapproved requests through submit path without waiting for approval", func() {
		testScheme := buildTestScheme()
		issuer := readyIssuer("ns-b", "issuer-b")
		secret := issuerSecret("ns-b")
		certificateRequest := certificateRequestForTests("ns-b", "req-not-approved", "issuer-b", false)

		fakeClient := fake.NewClientBuilder().
			WithScheme(testScheme).
			WithStatusSubresource(&cmapi.CertificateRequest{}, &horizonapi.Issuer{}).
			WithObjects(issuer, secret, certificateRequest).
			Build()

		reconciler := newCertificateRequestReconcilerForTests(fakeClient, testScheme, "ns-b")
		result, err := reconciler.Reconcile(ctx, ctrl.Request{
			NamespacedName: types.NamespacedName{
				Namespace: "ns-b",
				Name:      "req-not-approved",
			},
		})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("certificates.cert-manager.io \"missing-cert\" not found"))
		Expect(result).To(Equal(ctrl.Result{}))

		var updated cmapi.CertificateRequest
		Expect(fakeClient.Get(ctx, types.NamespacedName{Namespace: "ns-b", Name: "req-not-approved"}, &updated)).To(Succeed())
		Expect(cmutil.CertificateRequestIsApproved(&updated)).To(BeFalse())

		ready := cmutil.GetCertificateRequestCondition(&updated, cmapi.CertificateRequestConditionReady)
		Expect(ready).NotTo(BeNil())
		Expect(ready.Status).To(Equal(cmmeta.ConditionFalse))
		Expect(ready.Reason).To(Equal(cmapi.CertificateRequestReasonPending))
	})

	It("should retry status update on conflict and keep concurrent approval", func() {
		testScheme := buildTestScheme()
		issuer := readyIssuer("ns-c", "issuer-c")
		secret := issuerSecret("ns-c")
		certificateRequest := certificateRequestForTests("ns-c", "req-status-conflict", "issuer-c", false)
		name := types.NamespacedName{Namespace: "ns-c", Name: "req-status-conflict"}

		statusUpdates := 0
		fakeClient := fake.NewClientBuilder().
			WithScheme(testScheme).
			WithStatusSubresource(&cmapi.CertificateRequest{}, &horizonapi.Issuer{}).
			WithObjects(issuer, secret, certificateRequest).
			WithInterceptorFuncs(interceptor.Funcs{
				SubResourceUpdate: func(ctx context.Context, c client.Client, subResourceName string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
					statusUpdates++
					if statusUpdates == 1 {
						approveConcurrently(ctx, c, name)
					}
					return c.SubResource(subResourceName).Update(ctx, obj, opts...)
				},
			}).
			Build()

		reconciler := newCertificateRequestReconcilerForTests(fakeClient, testScheme, "ns-c")
		result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: name})

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("certificates.cert-manager.io \"missing-cert\" not found"))
		Expect(err.Error()).NotTo(ContainSubstring("the object has been modified"))
		Expect(result).To(Equal(ctrl.Result{}))
		Expect(statusUpdates).To(Equal(2))

		var updated cmapi.CertificateRequest
		Expect(fakeClient.Get(ctx, name, &updated)).To(Succeed())
		Expect(cmutil.CertificateRequestIsApproved(&updated)).To(BeTrue())

		ready := cmutil.GetCertificateRequestCondition(&updated, cmapi.CertificateRequestConditionReady)
		Expect(ready).NotTo(BeNil())
		Expect(ready.Status).To(Equal(cmmeta.ConditionFalse))
		Expect(ready.Reason).To(Equal(cmapi.CertificateRequestReasonPending))
	})

	It("should retry metadata update on conflict and merge concurrent changes", func() {
		testScheme := buildTestScheme()
		certificateRequest := certificateRequestForTests("ns-d", "req-metadata-conflict", "issuer-d", true)
		name := types.NamespacedName{Namespace: "ns-d", Name: "req-metadata-conflict"}

		updates := 0
		fakeClient := fake.NewClientBuilder().
			WithScheme(testScheme).
			WithObjects(certificateRequest).
			WithInterceptorFuncs(interceptor.Funcs{
				Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
					updates++
					if updates == 1 {
						// Simulate another controller annotating the object concurrently, making obj stale
						var latest cmapi.CertificateRequest
						Expect(c.Get(ctx, name, &latest)).To(Succeed())
						latest.Annotations["example.com/concurrent"] = "true"
						Expect(c.Update(ctx, &latest)).To(Succeed())
					}
					return c.Update(ctx, obj, opts...)
				},
			}).
			Build()

		var desired cmapi.CertificateRequest
		Expect(fakeClient.Get(ctx, name, &desired)).To(Succeed())
		desired.Annotations["horizon.evertrust.io/request-id"] = "request-123"
		desired.Finalizers = append(desired.Finalizers, FinalizerName)

		reconciler := newCertificateRequestReconcilerForTests(fakeClient, testScheme, "ns-d")
		Expect(reconciler.updateCertificateRequestMetadataWithRetry(ctx, name, &desired)).To(Succeed())
		Expect(updates).To(Equal(2))

		var updated cmapi.CertificateRequest
		Expect(fakeClient.Get(ctx, name, &updated)).To(Succeed())
		Expect(updated.Annotations).To(HaveKeyWithValue("horizon.evertrust.io/request-id", "request-123"))
		Expect(updated.Annotations).To(HaveKeyWithValue("example.com/concurrent", "true"))
		Expect(updated.Finalizers).To(ContainElement(FinalizerName))
	})

	It("should not retry metadata update on non-conflict errors", func() {
		testScheme := buildTestScheme()
		certificateRequest := certificateRequestForTests("ns-e", "req-metadata-error", "issuer-e", true)
		name := types.NamespacedName{Namespace: "ns-e", Name: "req-metadata-error"}

		updates := 0
		fakeClient := fake.NewClientBuilder().
			WithScheme(testScheme).
			WithObjects(certificateRequest).
			WithInterceptorFuncs(interceptor.Funcs{
				Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
					updates++
					return errors.New("boom")
				},
			}).
			Build()

		var desired cmapi.CertificateRequest
		Expect(fakeClient.Get(ctx, name, &desired)).To(Succeed())
		desired.Annotations["horizon.evertrust.io/request-id"] = "request-123"

		reconciler := newCertificateRequestReconcilerForTests(fakeClient, testScheme, "ns-e")
		Expect(reconciler.updateCertificateRequestMetadataWithRetry(ctx, name, &desired)).To(MatchError("boom"))
		Expect(updates).To(Equal(1))
	})

	It("should leave the Approved condition to the cluster's approval policies", func() {
		By("not approving a request nobody has decided on")
		latest := certificateRequestForTests("ns-f", "req", "issuer-f", false)
		desired := latest.DeepCopy()
		cmutil.SetCertificateRequestCondition(desired, cmapi.CertificateRequestConditionReady, cmmeta.ConditionTrue,
			cmapi.CertificateRequestReasonIssued, "Signed")

		copyManagedStatusFields(latest, desired)

		Expect(cmutil.GetCertificateRequestCondition(latest, cmapi.CertificateRequestConditionApproved)).To(BeNil())
		ready := cmutil.GetCertificateRequestCondition(latest, cmapi.CertificateRequestConditionReady)
		Expect(ready).NotTo(BeNil())
		Expect(ready.Reason).To(Equal(cmapi.CertificateRequestReasonIssued))

		By("keeping an approval set by another approver as is")
		latest = certificateRequestForTests("ns-g", "req", "issuer-g", true)
		desired = latest.DeepCopy()
		cmutil.SetCertificateRequestCondition(desired, cmapi.CertificateRequestConditionApproved, cmmeta.ConditionTrue,
			"horizon.evertrust.io", "Request approved on Horizon")

		copyManagedStatusFields(latest, desired)

		approved := cmutil.GetCertificateRequestCondition(latest, cmapi.CertificateRequestConditionApproved)
		Expect(approved).NotTo(BeNil())
		Expect(approved.Reason).To(Equal("cert-manager.io"))
		Expect(approved.Message).To(Equal("approved for tests"))
	})
})

func approveConcurrently(ctx context.Context, c client.Client, name types.NamespacedName) {
	var latest cmapi.CertificateRequest
	Expect(c.Get(ctx, name, &latest)).To(Succeed())
	cmutil.SetCertificateRequestCondition(
		&latest,
		cmapi.CertificateRequestConditionApproved,
		cmmeta.ConditionTrue,
		"cert-manager.io",
		"approved concurrently",
	)
	Expect(c.Status().Update(ctx, &latest)).To(Succeed())
}

func buildTestScheme() *runtime.Scheme {
	testScheme := runtime.NewScheme()
	Expect(corev1.AddToScheme(testScheme)).To(Succeed())
	Expect(horizonapi.AddToScheme(testScheme)).To(Succeed())
	Expect(cmapi.AddToScheme(testScheme)).To(Succeed())
	return testScheme
}

func newCertificateRequestReconcilerForTests(cl client.Client, sch *runtime.Scheme, clusterResourceNamespace string) *CertificateRequestReconciler {
	return &CertificateRequestReconciler{
		Client:                   cl,
		Scheme:                   sch,
		Recorder:                 record.NewFakeRecorder(10),
		ClusterResourceNamespace: clusterResourceNamespace,
		Clock:                    clock.RealClock{},
	}
}

// issuerAuthSecretName is the secret every test issuer authenticates with.
const issuerAuthSecretName = "issuer-auth"

func readyIssuer(namespace, name string) *horizonapi.Issuer {
	return &horizonapi.Issuer{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: horizonapi.IssuerSpec{
			URL:            "https://horizon.example",
			Profile:        "default",
			AuthSecretName: issuerAuthSecretName,
		},
		Status: horizonapi.IssuerStatus{
			Conditions: []metav1.Condition{
				{
					Type:               string(horizonapi.IssuerConditionReady),
					Status:             metav1.ConditionTrue,
					LastTransitionTime: metav1.Now(),
					Reason:             "Success",
					Message:            "Ready for tests",
					ObservedGeneration: 1,
				},
			},
		},
	}
}

func issuerSecret(namespace string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      issuerAuthSecretName,
			Namespace: namespace,
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"username": []byte("test"),
			"password": []byte("test"),
		},
	}
}

func certificateRequestForTests(namespace, name, issuerName string, approved bool) *cmapi.CertificateRequest {
	certificateRequest := &cmapi.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Annotations: map[string]string{
				"cert-manager.io/certificate-name": "missing-cert",
			},
		},
		Spec: cmapi.CertificateRequestSpec{
			Request: []byte("dummy-csr"),
			IssuerRef: cmmeta.ObjectReference{
				Group: horizonapi.GroupVersion.Group,
				Kind:  "Issuer",
				Name:  issuerName,
			},
		},
	}

	if approved {
		cmutil.SetCertificateRequestCondition(
			certificateRequest,
			cmapi.CertificateRequestConditionApproved,
			cmmeta.ConditionTrue,
			"cert-manager.io",
			"approved for tests",
		)
	}

	return certificateRequest
}
