package horizon

import (
	"github.com/evertrust/horizon-go"
	horizonapi "github.com/evertrust/horizon-issuer/api/v1beta1"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

type HealthChecker interface {
	Check() error
}

type HealthCheckerBuilder func(*horizonapi.IssuerSpec, map[string][]byte) (*HorizonHealthChecker, error)

func HealthCheckerFromIssuer(issuerSpec *horizonapi.IssuerSpec, secretData map[string][]byte) (*HorizonHealthChecker, error) {
	client, err := ClientFromIssuer(issuerSpec, secretData)
	if err != nil {
		return nil, err
	}

	return &HorizonHealthChecker{Client: *client}, nil
}

type HorizonHealthChecker struct {
	Client horizon.Horizon
}

func (o *HorizonHealthChecker) Check() error {
	url := o.Client.Http.BaseUrl()
	logger := log.Log.
		WithName("horizon.healthcheck").
		WithValues("url", url.String())

	logger.V(1).Info("Client setup")
	_, err := o.Client.Http.Get("/api/v1/security/principals/self")
	if err != nil {
		logger.V(1).Info("Call to /api/v1/security/principals/self returned an error", "error", err.Error())
		return err
	}
	logger.V(1).Info("Call to /api/v1/security/principals/self returned no error")
	return nil
}
