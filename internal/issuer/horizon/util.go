package horizon

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/evertrust/horizon-go"
	"github.com/evertrust/horizon-go/rfc5280"
	horizonapi "github.com/evertrust/horizon-issuer/api/v1beta1"
	"gopkg.in/resty.v1"
	"net/url"
)

func ClientFromIssuer(issuerSpec *horizonapi.IssuerSpec, secretData map[string][]byte) (*horizon.Horizon, error) {
	client := new(horizon.Horizon)

	var tlsConfig = &tls.Config{
		InsecureSkipVerify: issuerSpec.SkipTLSVerify,
	}
	if issuerSpec.CaBundle != nil {
		tlsConfig.RootCAs = x509.NewCertPool()
		tlsConfig.RootCAs.AppendCertsFromPEM([]byte(*issuerSpec.CaBundle))
	}
	var restyClient = resty.New().SetTLSClientConfig(tlsConfig)
	client.Init(restyClient)

	baseUrl, err := url.Parse(issuerSpec.URL)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", "Invalid base URL", err)
	}
	username := string(secretData["username"])
	password := string(secretData["password"])
	client.Http.WithBaseUrl(*baseUrl)
	client.Http.WithPasswordAuth(username, password)

	return client, nil
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
