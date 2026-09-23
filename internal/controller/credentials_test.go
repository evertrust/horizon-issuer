package controller

import (
	"encoding/base64"
	"encoding/json"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	horizonapi "github.com/evertrust/horizon-issuer/api/v1beta1"
	horizonissuer "github.com/evertrust/horizon-issuer/internal/issuer/horizon"
)

// jwtAudiences reads the "aud" claim out of a JWT without checking its signature.
func jwtAudiences(token string) []string {
	parts := strings.Split(token, ".")
	Expect(parts).To(HaveLen(3), "token is not a JWT")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	Expect(err).NotTo(HaveOccurred())
	var claims struct {
		Audience []string `json:"aud"`
	}
	Expect(json.Unmarshal(payload, &claims)).To(Succeed())
	return claims.Audience
}

var _ = Describe("Issuer credentials", func() {
	const namespace = "default"
	const horizonURL = "https://horizon.example.com"
	const horizonServiceAccount = "horizon-issuer"

	var serviceAccount *corev1.ServiceAccount

	BeforeEach(func() {
		serviceAccount = &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "horizon-sa-",
				Namespace:    namespace,
			},
		}
		Expect(k8sClient.Create(ctx, serviceAccount)).To(Succeed())
		DeferCleanup(func() {
			Expect(k8sClient.Delete(ctx, serviceAccount)).To(Succeed())
		})
	})

	It("requests a token bound to the Horizon URL by default", func() {
		spec := &horizonapi.IssuerSpec{
			URL: horizonURL,
			ServiceAccount: &horizonapi.IssuerServiceAccount{
				Name:              horizonServiceAccount,
				ServiceAccountRef: horizonapi.ServiceAccountRef{Name: serviceAccount.Name},
			},
		}

		creds, err := credentialsFromIssuer(ctx, k8sClient, spec, namespace)
		Expect(err).NotTo(HaveOccurred())
		Expect(creds.Secret).To(BeNil())
		Expect(creds.ServiceAccount).NotTo(BeNil())
		Expect(creds.ServiceAccount.Name).To(Equal(horizonServiceAccount))

		token, err := creds.ServiceAccount.Token(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(jwtAudiences(token)).To(ConsistOf(horizonURL))

		By("returning the cached token on the second call")
		again, err := creds.ServiceAccount.Token(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(again).To(Equal(token))
	})

	It("honors explicit audiences and expiration", func() {
		expiration := int64(3600)
		provider := horizonissuer.TokenRequestProvider(k8sClient, types.NamespacedName{
			Name:      serviceAccount.Name,
			Namespace: namespace,
		}, []string{"aud-1", "aud-2"}, expiration)

		token, err := provider(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(jwtAudiences(token)).To(ConsistOf("aud-1", "aud-2"))
	})

	It("fails when the Kubernetes ServiceAccount does not exist", func() {
		spec := &horizonapi.IssuerSpec{
			URL: horizonURL,
			ServiceAccount: &horizonapi.IssuerServiceAccount{
				Name:              horizonServiceAccount,
				ServiceAccountRef: horizonapi.ServiceAccountRef{Name: "does-not-exist"},
			},
		}
		creds, err := credentialsFromIssuer(ctx, k8sClient, spec, namespace)
		Expect(err).NotTo(HaveOccurred())
		_, err = creds.ServiceAccount.Token(ctx)
		Expect(err).To(HaveOccurred())
	})

	It("loads the referenced secret", func() {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "horizon-creds-", Namespace: namespace},
			Type:       corev1.SecretTypeOpaque,
			StringData: map[string]string{"username": "user", "password": "pass"},
		}
		Expect(k8sClient.Create(ctx, secret)).To(Succeed())
		DeferCleanup(func() {
			Expect(k8sClient.Delete(ctx, secret)).To(Succeed())
		})

		spec := &horizonapi.IssuerSpec{URL: horizonURL, AuthSecretName: secret.Name}
		creds, err := credentialsFromIssuer(ctx, k8sClient, spec, namespace)
		Expect(err).NotTo(HaveOccurred())
		Expect(creds.ServiceAccount).To(BeNil())
		Expect(creds.Secret).NotTo(BeNil())
		Expect(creds.Secret.Name).To(Equal(secret.Name))
	})

	It("fails when the secret is missing", func() {
		spec := &horizonapi.IssuerSpec{URL: horizonURL, AuthSecretName: "missing"}
		_, err := credentialsFromIssuer(ctx, k8sClient, spec, namespace)
		Expect(err).To(MatchError(errGetAuthSecret))
	})

	It("fails when no authentication method is configured", func() {
		_, err := credentialsFromIssuer(ctx, k8sClient, &horizonapi.IssuerSpec{URL: horizonURL}, namespace)
		Expect(err).To(MatchError(errNoAuthMethod))
	})
})
