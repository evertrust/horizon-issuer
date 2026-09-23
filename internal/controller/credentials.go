package controller

import (
	"context"
	"errors"
	"fmt"

	horizonapi "github.com/evertrust/horizon-issuer/api/v1beta1"
	horizonissuer "github.com/evertrust/horizon-issuer/internal/issuer/horizon"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const defaultTokenExpirationSeconds int64 = 600

var errNoAuthMethod = errors.New("no authentication method configured on the issuer: set either authSecretName or serviceAccount")

// +kubebuilder:rbac:groups=core,resources=serviceaccounts/token,verbs=create

// credentialsFromIssuer resolves the Horizon credentials configured on an
// issuer. namespace is where the referenced Secret or ServiceAccount lives:
// the Issuer's own namespace, or the cluster resource namespace for a
// ClusterIssuer.
func credentialsFromIssuer(ctx context.Context, k8sClient client.Client, issuerSpec *horizonapi.IssuerSpec, namespace string) (horizonissuer.Credentials, error) {
	switch {
	case issuerSpec.ServiceAccount != nil:
		return serviceAccountCredentials(k8sClient, issuerSpec, namespace), nil
	case issuerSpec.AuthSecretName != "":
		secretName := types.NamespacedName{
			Name:      issuerSpec.AuthSecretName,
			Namespace: namespace,
		}
		var secret corev1.Secret
		if err := k8sClient.Get(ctx, secretName, &secret); err != nil {
			return horizonissuer.Credentials{}, fmt.Errorf("%w, secret name: %s, reason: %v", errGetAuthSecret, secretName, err)
		}
		return horizonissuer.SecretCredentials(secret), nil
	default:
		return horizonissuer.Credentials{}, errNoAuthMethod
	}
}

func serviceAccountCredentials(k8sClient client.Client, issuerSpec *horizonapi.IssuerSpec, namespace string) horizonissuer.Credentials {
	sa := issuerSpec.ServiceAccount
	ref := sa.ServiceAccountRef

	audiences := ref.Audiences
	if len(audiences) == 0 {
		audiences = []string{issuerSpec.URL}
	}
	expiration := defaultTokenExpirationSeconds
	if ref.ExpirationSeconds != nil {
		expiration = *ref.ExpirationSeconds
	}

	return horizonissuer.Credentials{
		ServiceAccount: &horizonissuer.ServiceAccountCredentials{
			Name: sa.Name,
			Token: horizonissuer.TokenRequestProvider(k8sClient, types.NamespacedName{
				Name:      ref.Name,
				Namespace: namespace,
			}, audiences, expiration),
		},
	}
}
