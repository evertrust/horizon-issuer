package horizon

import (
	horizonclient "github.com/evertrust/horizon-go/client"
	horizonapi "github.com/evertrust/horizon-issuer/api/v1beta1"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

type HealthChecker interface {
	Check() error
}

type HealthCheckerBuilder func(logr.Logger, *horizonapi.IssuerSpec, corev1.Secret) (*HorizonHealthChecker, error)

func HealthCheckerFromIssuer(log logr.Logger, issuerSpec *horizonapi.IssuerSpec, secret corev1.Secret) (*HorizonHealthChecker, error) {
	client, err := ClientFromIssuer(log, issuerSpec, secret)
	if err != nil {
		return nil, err
	}

	return &HorizonHealthChecker{Client: *client}, nil
}

type HorizonHealthChecker struct {
	Client horizonclient.Client
}

func (o *HorizonHealthChecker) Check() error {
	url, _ := o.Client.Http.BaseUrl()
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
