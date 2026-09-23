package horizon

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/evertrust/horizon-go/v2"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// tokenRefreshMargin is how long before expiry a cached token is replaced.
const tokenRefreshMargin = time.Minute

var errNoCredentials = errors.New("no authentication method configured: set either authSecretName or serviceAccount")

// TokenProvider returns the JWT to send to Horizon. The SDK calls it on every
// request, so implementations should be cheap or cache their result.
type TokenProvider func(ctx context.Context) (string, error)

// ServiceAccountCredentials authenticates against Horizon as a JWKS service
// account.
type ServiceAccountCredentials struct {
	// Name is the Horizon service account name (X-API-SVA header).
	Name string
	// Token provides the JWT (X-API-TOKEN header).
	Token TokenProvider
}

// Credentials is what a Horizon client authenticates with. Set exactly one of
// Secret or ServiceAccount.
type Credentials struct {
	// Secret holds static credentials: an Opaque secret with username/password
	// keys, or a TLS secret with a client certificate.
	Secret *corev1.Secret
	// ServiceAccount holds JWKS service account credentials.
	ServiceAccount *ServiceAccountCredentials
}

// SecretCredentials builds Credentials from a static Secret.
func SecretCredentials(secret corev1.Secret) Credentials {
	return Credentials{Secret: &secret}
}

// Context attaches the service account credentials to ctx. The Horizon SDK
// reads them from the context and sets the X-API-SVA and X-API-TOKEN headers
// on each request. Secret credentials live on the client configuration
// instead, so for them ctx is returned as is.
func (c Credentials) Context(ctx context.Context) context.Context {
	if c.ServiceAccount == nil {
		return ctx
	}
	sa := c.ServiceAccount
	return horizon.WithServiceAccount(ctx, sa.Name, func() (string, error) {
		return sa.Token(ctx)
	})
}

func (c Credentials) validate() error {
	switch {
	case c.Secret != nil && c.ServiceAccount != nil:
		return errors.New("both a secret and a service account were provided, only one is allowed")
	case c.ServiceAccount != nil:
		if c.ServiceAccount.Name == "" {
			return errors.New("service account name is empty")
		}
		if c.ServiceAccount.Token == nil {
			return errors.New("service account token provider is nil")
		}
		return nil
	case c.Secret != nil:
		return nil
	default:
		return errNoCredentials
	}
}

// TokenRequestProvider mints a token for a Kubernetes ServiceAccount through
// the TokenRequest API. The token is cached and requested again one minute
// before it expires.
func TokenRequestProvider(k8sClient client.Client, serviceAccount types.NamespacedName, audiences []string, expirationSeconds int64) TokenProvider {
	var (
		mu     sync.Mutex
		token  string
		expiry time.Time
	)

	return func(ctx context.Context) (string, error) {
		mu.Lock()
		defer mu.Unlock()

		if token != "" && time.Now().Before(expiry.Add(-tokenRefreshMargin)) {
			return token, nil
		}

		tokenRequest := &authenticationv1.TokenRequest{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authenticationv1.SchemeGroupVersion.String(),
				Kind:       "TokenRequest",
			},
			Spec: authenticationv1.TokenRequestSpec{
				Audiences:         audiences,
				ExpirationSeconds: &expirationSeconds,
			},
		}
		sa := &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      serviceAccount.Name,
				Namespace: serviceAccount.Namespace,
			},
		}

		if err := k8sClient.SubResource("token").Create(ctx, sa, tokenRequest); err != nil {
			return "", fmt.Errorf("unable to request a token for service account %s: %w", serviceAccount, err)
		}
		if tokenRequest.Status.Token == "" {
			return "", fmt.Errorf("token request for service account %s returned an empty token", serviceAccount)
		}

		token = tokenRequest.Status.Token
		expiry = tokenRequest.Status.ExpirationTimestamp.Time
		return token, nil
	}
}
