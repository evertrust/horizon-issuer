package horizon

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/evertrust/horizon-go/v2"
	"github.com/evertrust/horizon-go/v2/models"
	horizonapi "github.com/evertrust/horizon-issuer/api/v1beta1"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
)

func ClientFromIssuer(log logr.Logger, issuerSpec *horizonapi.IssuerSpec, secret corev1.Secret) (*horizon.APIClient, error) {
	config := horizon.NewConfiguration()
	issuerSpec.URL = strings.TrimSuffix(issuerSpec.URL, "/")

	config.Servers = horizon.ServerConfigurations{{
		URL: issuerSpec.URL,
	}}

	config.Scheme = ""

	tlsConfig := config.GetTlsConfig()
	if issuerSpec.SkipTLSVerify {
		log.Info("Skipping TLS verification. Not recommended in production.")
		tlsConfig.InsecureSkipVerify = true
	}
	if issuerSpec.CaBundle != nil {
		log.V(1).Info(fmt.Sprintf("Adding custom CA bundle to trust store: %q", *issuerSpec.CaBundle))
		tlsConfig.RootCAs = x509.NewCertPool()
		ok := tlsConfig.RootCAs.AppendCertsFromPEM([]byte(*issuerSpec.CaBundle))
		if !ok {
			return nil, fmt.Errorf("failed to parse root certificate")
		}
	}

	if issuerSpec.Proxy != nil {
		proxyUrl, err := url.Parse(*issuerSpec.Proxy)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", "Invalid proxy URL", err)
		}
		config.SetProxyUrl(proxyUrl)
	}

	switch secret.Type {
	case corev1.SecretTypeTLS:
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
		config.SetCertAuth(cert)
	case corev1.SecretTypeOpaque:
		if _, ok := secret.Data["username"]; !ok {
			return nil, fmt.Errorf("%s: %v", "Missing username in secret", secret.Name)
		}
		if _, ok := secret.Data["password"]; !ok {
			return nil, fmt.Errorf("%s: %v", "Missing password in secret", secret.Name)
		}
		config.SetPasswordAuth(string(secret.Data["username"]), string(secret.Data["password"]))
	default:
		return nil, fmt.Errorf("%s: %v", "Unsupported secret type", secret.Type)
	}

	client := horizon.NewAPIClient(config)
	return client, nil
}

func FormatAPIError(err error) string {
	if err == nil {
		return ""
	}
	var apiErr *horizon.GenericOpenAPIError
	if errors.As(err, &apiErr) {
		if be, ok := apiErr.Model().(models.BasicError); ok {
			if msg := formatBasicError(&be); msg != "" {
				return msg
			}
		}
	}
	return err.Error()
}

func formatBasicError(be *models.BasicError) string {
	var parts []string
	if code := be.GetError(); code != "" {
		parts = append(parts, code)
	}
	summary := be.GetTitle()
	if summary == "" {
		summary = be.GetMessage()
	}
	if be.HasDetail() {
		detail := be.GetDetail()
		if summary != "" && detail != "" {
			summary = fmt.Sprintf("%s: %s", summary, detail)
		} else if detail != "" {
			summary = detail
		}
	}
	if summary != "" {
		parts = append(parts, summary)
	}
	return strings.Join(parts, " - ")
}

// buildPemTrustchain constructs a PEM-encoded leaf-to-root trust chain, given a collection
// of rfc5280.CfCertificate objects in the leaf-to-root order. If present at the end of the chain,
// the certification authority will also be returned.
func buildPemTrustchain(certs []models.CFCertificateResponse) (chain string, ca string) {
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
