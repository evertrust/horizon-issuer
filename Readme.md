<h1 align="center">Horizon Issuer</h1>

> A cert-manager issuer allowing you to use your Horizon instance to centralize your Kubernetes certificates issuance.

## Prerequisites

This software has been testing against the following environment :

- Horizon version 2.2.0 and above
- Kubernetes version 1.22 and above

## Installation

Add EverTrust's Helm repository to your local repositories :

```shell
helm repo add evertrust https://repo.evertrust.io/repository/charts
```

Install the chart in your cluster :

```shell
helm install cm evertrust/horizon-issuer
```

The default configuration should be fine for most cases. If you want to check out the configuration options, see
the [values.yaml](charts/horizon-issuer/values.yaml) file.

Since the chart installs CRDs, please ensure that you have the appropriate permissions when installing it.

## Usage

### Setting up an Horizon issuer

Create an `Issuer` or `ClusterIssuer` object depending on the scope you want to issue certificates on :

```yaml
apiVersion: horizon.evertrust.io/v1alpha1
kind: ClusterIssuer
metadata:
  name: horizon-clusterissuer
spec:
  url: <horizon instance URL> # https://you.evertrust.io
  authSecretName: horizon-credentials
  profile: IssuerProfile
```

Then, provide your Horizon credentials in a secret you may create with :

```shell
kubectl create secret generic issuer-sample-credentials \
 --from-literal=username=<horizon username> \
 --from-literal=password=<horizon password>
```

### Issuing certificates

Now that your issuer is set up, you may reference it when issuing new certificates. This can be done by setting
the `issuerRef` key on that certificate :

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: demo-cert
spec:
  commonName: demo.org
  secretName: demo-cert
  issuerRef:
    group: horizon.evertrust.io
    kind: ClusterIssuer
    name: horizon-clusterissuer
```

### Securing ingresses

If you are using `ingress-shim` to secure your ingress resources, reference your issuer using the following annotations
when creating your ingress :

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: demo-ingress
  annotations:
    cert-manager.io/issuer-group: horizon.evertrust.io
    cert-manager.io/issuer-kind: ClusterIssuer
    cert-manager.io/issuer: horizon-clusterissuer
    cert-manager.io/common-name: demo.org
```

> **Warning** : be sure to set the `cert-manager.io/common-name` annotation as by default, ingress-shim will generate
> certificates without any DN. This will cause errors on Horizon's side.

### Using labels, owners and teams

Horizon offers useful features to categorize and better understand your certificates through metadata. You may specify
metadata at three levels :

#### On an ingress object

You may use the following annotations on ingresses that will be reflected onto the enrolled certificate :

```yaml
horizon.evertrust.io/owner: owner-name
horizon.evertrust.io/team: team-name
```

#### On a certificate object

You may use the following annotations on the cert-manager `Certificate` object, that will be reflected onto the enrolled
certificate :

```yaml
horizon.evertrust.io/owner: owner-name
horizon.evertrust.io/team: team-name
```

These values, if set, will take precedence over annotations on an `Ingress` object.

#### On a `ClusterIssuer` or `Issuer` object

You may configure your issuer to apply certain metadata to every certificate enrolled through it, by modifying its spec.
The following keys are available :

```yaml
apiVersion: horizon.evertrust.io/v1alpha1
kind: ClusterIssuer
spec:
  owner: owner-name
  team: team-name
  labels:
    label-key: label-value
```

These values, if set, will take precedence over annotations on an `Ingress` or `Certificate` object.

## Configuration

### Trusting custom CAs

Your Horizon instance may be presenting a certificate issued by your custom CA. To trust that certificate, you may
specify a CA bundle when creating the issuer through the `caBundle` field. You may also completely disable TLS
verification by setting `skipTLSVerify` to `true`, this is however highly discouraged.

Example :

```yaml
apiVersion: horizon.evertrust.io/v1alpha1
kind: ClusterIssuer
spec:
  caBundle: |
    -----BEGIN CERTIFICATE-----
    ...
    -----END CERTIFICATE-----
  skipTLSVerify: false
```

You can also mount your custom `/etc/ssl/certs` directory if you wish to have more control over the underlying OS trust
store.

### Revoking deleted certificates

By default, Horizon issuer does not revoke certificates deleted from Kubernetes as cert-manager can reuse the private
key kept in the deleted certificate's secret.
If you want to revoke certificates are they are deleted, set the `revokeCertificates` property to `true` on
your `Issuer` or `ClusterIssuer` object. When doing so, you may want
to [clean up secrets as soon as certificates are revoked](https://cert-manager.io/docs/usage/certificate/#cleaning-up-secrets-when-certificates-are-deleted)
.

### Validate the certificate FQDN

In case you want to enforce the coherence of your infrastructure, we offer a DNS validation feature. When enabled, the
issuer will check that a DNS entry matching the certificate CN and every DNS SANs exist. If not, the certificate will
not be issued. To enable, add the following key to your `Issuer` object :

```yaml
spec:
  dnsChecker:
    server: 8.8.8.8:53
```