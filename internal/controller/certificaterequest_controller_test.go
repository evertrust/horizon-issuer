package controller

import (
	"time"

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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("CertificateRequestReconciler", func() {
	It("should process approved requests without request-id through submit path", func() {
		testScheme := buildTestScheme()
		issuer := readyIssuer("ns-a", "issuer-a", "issuer-auth")
		secret := issuerSecret("ns-a", "issuer-auth")
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

	It("should wait for approval before submit path", func() {
		testScheme := buildTestScheme()
		issuer := readyIssuer("ns-b", "issuer-b", "issuer-auth")
		secret := issuerSecret("ns-b", "issuer-auth")
		certificateRequest := certificateRequestForTests("ns-b", "req-pending-approval", "issuer-b", false)

		fakeClient := fake.NewClientBuilder().
			WithScheme(testScheme).
			WithStatusSubresource(&cmapi.CertificateRequest{}, &horizonapi.Issuer{}).
			WithObjects(issuer, secret, certificateRequest).
			Build()

		reconciler := newCertificateRequestReconcilerForTests(fakeClient, testScheme, "ns-b")
		result, err := reconciler.Reconcile(ctx, ctrl.Request{
			NamespacedName: types.NamespacedName{
				Namespace: "ns-b",
				Name:      "req-pending-approval",
			},
		})

		Expect(err).NotTo(HaveOccurred())
		Expect(result.RequeueAfter).To(Equal(5 * time.Second))

		var updated cmapi.CertificateRequest
		Expect(fakeClient.Get(ctx, types.NamespacedName{Namespace: "ns-b", Name: "req-pending-approval"}, &updated)).To(Succeed())

		ready := cmutil.GetCertificateRequestCondition(&updated, cmapi.CertificateRequestConditionReady)
		Expect(ready).NotTo(BeNil())
		Expect(ready.Status).To(Equal(cmmeta.ConditionFalse))
		Expect(ready.Reason).To(Equal(cmapi.CertificateRequestReasonPending))
		Expect(ready.Message).To(Equal("Waiting for approval"))
	})
})

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

func readyIssuer(namespace, name, secretName string) *horizonapi.Issuer {
	return &horizonapi.Issuer{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: horizonapi.IssuerSpec{
			URL:            "https://horizon.example",
			Profile:        "default",
			AuthSecretName: secretName,
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

func issuerSecret(namespace, name string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
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
