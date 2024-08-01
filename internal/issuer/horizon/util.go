package horizon

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/evertrust/horizon-go/client"
	"github.com/evertrust/horizon-go/rfc5280"
	horizonapi "github.com/evertrust/horizon-issuer/api/v1beta1"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"net/url"
)

func ClientFromIssuer(log logr.Logger, issuerSpec *horizonapi.IssuerSpec, secret corev1.Secret) (*client.Client, error) {
	horizon := client.New(nil)

	if issuerSpec.SkipTLSVerify {
		log.Info("Skipping TLS verification. Not recommended in production.")
		horizon.SkipTLSVerify()
	}
	if issuerSpec.CaBundle != nil {
		log.V(1).Info(fmt.Sprintf("Adding custom CA bundle to trust store: %q", *issuerSpec.CaBundle))
		rootCAs := x509.NewCertPool()
		ok := rootCAs.AppendCertsFromPEM([]byte(*issuerSpec.CaBundle))
		if !ok {
			return nil, fmt.Errorf("failed to parse root certificate")
		}
		horizon.SetCaBundle(rootCAs)
	}

	if issuerSpec.Proxy != nil {
		proxyUrl, err := url.Parse(*issuerSpec.Proxy)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", "Invalid proxy URL", err)
		}
		horizon.SetProxy(*proxyUrl)
	}

	baseUrl, err := url.Parse(issuerSpec.URL)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", "Invalid base URL", err)
	}

	if secret.Type == corev1.SecretTypeTLS {
		if _, ok := secret.Data["tls.crt"]; !ok {
			return nil, fmt.Errorf("%s: %v", "Missing tls.crt in secret", secret.Name)
		}
		if _, ok := secret.Data["tls.key"]; !ok {
			return nil, fmt.Errorf("%s: %v", "Missing tls.key in secret", secret.Name)
		}

		cert, err := tls.X509KeyPair(secret.Data["tls.crt"], secret.Data["tls.key"])
		if err != nil {
			return nil, fmt.Errorf("%s: %v", "Failed to load TLS certificate", err)
		}

		horizon.SetCertAuth(cert)
	} else if secret.Type == corev1.SecretTypeOpaque {
		if _, ok := secret.Data["username"]; !ok {
			return nil, fmt.Errorf("%s: %v", "Missing username in secret", secret.Name)
		}
		if _, ok := secret.Data["password"]; !ok {
			return nil, fmt.Errorf("%s: %v", "Missing password in secret", secret.Name)
		}
		horizon.SetPasswordAuth(
			string(secret.Data["username"]),
			string(secret.Data["password"]),
		)
	} else {
		return nil, fmt.Errorf("%s: %v", "Unsupported secret type", secret.Type)
	}

	horizon.SetBaseUrl(*baseUrl)

	return horizon, nil
}

// BuildPemTrustchain constructs a PEM-encoded leaf-to-root trust chain, given a collection
// of rfc5280.CfCertificate objects in the leaf-to-root order. If present at the end of the chain,
// the certification authority will also be returned.
func BuildPemTrustchain(certs []rfc5280.CfCertificate) (chain string, ca string) {
	for i, certificate := range certs {
		if i == len(certs)-1 {
			if certificate.SelfSigned {
				// We found a root CA. Add it to the secret ca.crt key.
				ca = certificate.Pem
			} else {
				// Else, we just proceed to append it to our trustchain.
				chain += certificate.Pem
			}
		} else {
			// Append cert at the end of our trustchain
			chain += certificate.Pem + "\n"
		}
	}
	return chain, ca
}
