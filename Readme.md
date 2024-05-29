<h1 align="center">Horizon Issuer</h1>

> A cert-manager issuer allowing you to use your Horizon instance to centralize your Kubernetes certificates issuance.

## Prerequisites

Before installing, ensure the following prerequisites are met :

- This software requires Kubernetes version 1.22 and above.
- cert-manager must be installed in your cluster prior to installing this chart.
- The following compatibility matrix applies for Horizon versions :

| Issuer version | Horizon version |
|----------------|-----------------|
| 0.1.x          | 2.2.x /2.3.x    |
| 0.2.x          | 2.4.x           |
| 0.3.x          | 2.4.x           |

## Installation

Add EverTrust's Helm repository to your local repositories :

```shell
helm repo add evertrust https://repo.evertrust.io/repository/charts
```

Install the chart in your cluster :

```shell
helm install horizon-issuer evertrust/horizon-issuer
```

The default configuration should be fine for most cases. If you want to check out the configuration options, see
the [values.yaml](charts/horizon-issuer/values.yaml) file.

## Usage

### Setting up an Horizon issuer

First, provide your Horizon credentials in a secret you may create with :

```shell
kubectl create secret generic horizon-credentials \
 --from-literal=username=<horizon username> \
 --from-literal=password=<horizon password>
```

Alternatively, to authenticate using an X509 certificate, use a `kubernetes.io/tls` Secret instead:

```shell
kubectl create secret tls horizon-credentials \
  --cert=path/to/tls.crt \ 
  --key=path/to/tls.key
```

The principal should have the ability to enroll certificates on at least one WebRA profile. 
Then, create an `Issuer` or `ClusterIssuer` object depending on the scope you want to issue certificates on :

```yaml
apiVersion: horizon.evertrust.io/v1beta1
kind: ClusterIssuer
metadata:
  name: horizon-clusterissuer
spec:
  url: <horizon instance URL> # https://you.evertrust.io
  authSecretName: horizon-credentials
  profile: IssuerProfile
```

This object spec references the credentials secret we just created.

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

### Configure labels and certificate ownership

Horizon offers useful features to categorize and better understand your certificates through metadata. You may specify
metadata at multiple levels. Values get overridden in the following order of precedence:

1. Values set in the `defaultTemplate` object on an `Issuer` or `ClusterIssuer` object
2. Values set on annotations either on the `Ingress` or `Certificate` object
3. Values set in the `overrideTemplate` of an `Issuer` or `ClusterIssuer` object

#### Using `defaultTemplate` on an issuer

Default templates allows you to set default values for your certificates.
These values will be used if no other value is set by the user on the resource they are issuing.
On the `Issuer` or `ClusterIssuer` object, add the following key :

```yaml
apiVersion: horizon.evertrust.io/v1beta1
kind: ClusterIssuer
spec:
  profile: IssuerProfile
  url: https://you.evertrust.io
  defaultTemplate:
    owner: owner-name
    team: team-name
    contactEmail: owner-email@company.com
    labels:
      label-name1: label-value1
  authSecretName: horizon-credentials
```

#### On an `Ingress` or `Certificate` object

You may use the following annotations on ingresses that will be reflected onto the enrolled certificate :

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ingress-name
  annotations:
    horizon.evertrust.io/owner: owner-name
    horizon.evertrust.io/team: team-name
    horizon.evertrust.io/contact-email: owner-email@company.com
    horizon.evertrust.io/labels.label-name1: label-value1
    horizon.evertrust.io/labels.label-name2: label-value2
```

These values, if set, will take precedence over annotations on values set in the `defaultTemplate` key of the issuer.

#### Using `overrideTemplate` on an issuer

You may also want to ensure certain values are set on every certificate issued by a specific issuer.
This can be done using the `overrideTemplate` key on an `Issuer` or `ClusterIssuer` object. These values will take
precedence over any other value set on the issuer or on the resource being issued:

```yaml
apiVersion: horizon.evertrust.io/v1beta1
kind: ClusterIssuer
spec:
  profile: IssuerProfile
  url: https://you.evertrust.io
  overrideTemplate:
    owner: owner-name
    team: team-name
    contactEmail: owner-email@company.com
    labels:
      label-name1: label-value1
  authSecretName: horizon-credentials
```

These values, if set, will take precedence over annotations on an `Ingress` or `Certificate` object.

## Configuration

### Trusting custom CAs

Your Horizon instance may be presenting a certificate issued by your custom CA. To trust that certificate, you may
specify a CA bundle when creating the issuer through the `caBundle` field. You may also completely disable TLS
verification by setting `skipTLSVerify` to `true`, this is however highly discouraged.

Example :

```yaml
apiVersion: horizon.evertrust.io/v1beta1
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
your `Issuer` or `ClusterIssuer` object :

```yaml
apiVersion: horizon.evertrust.io/v1beta1
kind: ClusterIssuer
spec:
  revokeCertificates: true
```

When doing so, you may want
to [clean up secrets as soon as certificates are revoked](https://cert-manager.io/docs/usage/certificate/#cleaning-up-secrets-when-certificates-are-deleted).

### Using an outbound proxy

If you need to use an outbound proxy to reach your Horizon instance, you may specify it in the `proxy` field of your
`Issuer` or `ClusterIssuer` object :

```yaml
apiVersion: horizon.evertrust.io/v1beta1
kind: ClusterIssuer
spec:
  proxy: http://proxy.example.com:8080
```

### Validate the certificate FQDN

In case you want to enforce the coherence of your infrastructure, we offer a DNS validation feature. When enabled, the
issuer will check that a DNS entry matching the certificate CN and every DNS SANs exist. If not, the certificate will
not be issued. To enable, add the following key to your `Issuer` object :

```yaml
apiVersion: horizon.evertrust.io/v1beta1
kind: ClusterIssuer
spec:
  dnsChecker:
    server: 8.8.8.8:53
```

## CRD considerations

`horizon-issuer` needs CRDs to properly work. Similarly to
what [cert-manager](https://cert-manager.io/docs/installation/helm/#3-install-customresourcedefinitions) offers, you
have two options when installing the chart :

### Option 1 : Manage CRDs manually

You can manually install the CRDs using `kubectl`. In that case, the following commands before installing or upgrading
the chart:

```shell
kubectl apply -f https://raw.githubusercontent.com/evertrust/horizon-issuer/v0.3.0/charts/horizon-issuer/crds/horizon.evertrust.io_clusterissuers.yaml
kubectl apply -f https://raw.githubusercontent.com/evertrust/horizon-issuer/v0.3.0/charts/horizon-issuer/crds/horizon.evertrust.io_issuers.yaml
```

This ensures that the CRDs are not upgraded by mistake. However, it requires you to manually upgrade the CRDs when a new
version is released. If you opt for this method, ensure that the `installCRDs` key is set to `false` in your Helm.

### Option 2 : Let the Helm chart manage CRDs

You can let the Helm chart manage the CRDs for you. In that case, the CRDs will be installed and upgraded automatically
when installing or upgrading the chart. To do so, ensure that the `installCRDs` key is set to `true` in your Helm.

> [!NOTE]  
> We generally recommend that you use the same method that you use to manage CRDs for the main `cert-manager`
> deployment.

## Migration

### Migrating from v0.2.0 to v0.3.0

In 0.3.0, the CRDs can be managed by the Helm chart itself, similarly to
what [cert-manager](https://cert-manager.io/docs/installation/helm/#3-install-customresourcedefinitions) offers. It
means that you have [two options](#crd-considerations) when upgrading.

Should you decide to manage CRDs automatically through the Helm chart, you'll need to update existing CRDs before
upgrading so that they can be managed by the Helm chart. The following commands are required :

```shell
kubectl label crd/clusterissuers.horizon.evertrust.io app.kubernetes.io/managed-by=Helm
kubectl label crd/issuers.horizon.evertrust.io app.kubernetes.io/managed-by=Helm

kubectl annotate crd/clusterissuers.horizon.evertrust.io meta.helm.sh/release-name=<horizon-issuer> meta.helm.sh/release-namespace=<horizon-issuer>
kubectl annotate crd/issuers.horizon.evertrust.io meta.helm.sh/release-name=<horizon-issuer> meta.helm.sh/release-namespace=<horizon-issuer>
```

Replace replace `release-name` with your Helm release name and `release-namespace` with the namespace you're installing
into.

### Migrating from v0.1.0 to v0.2.0

In 0.2.0, the new CRD version is `v1beta1`, and `v1alpha1` is no longer supported. To migrate from the old version, you
must first upgrade the CRDs:

```shell
kubectl apply -f https://raw.githubusercontent.com/evertrust/horizon-issuer/v0.2.0/charts/horizon-issuer/crds/horizon.evertrust.io_clusterissuers.yaml
kubectl apply -f https://raw.githubusercontent.com/evertrust/horizon-issuer/v0.2.0/charts/horizon-issuer/crds/horizon.evertrust.io_issuers.yaml
```

This will not delete your existing `Issuer` and `ClusterIssuer` objects, but will allow you to create resources with the
new `v1beta1` version.
After having re-created your issuer objects, you can start the upgrade using Helm :

```shell
helm upgrade horizon-issuer evertrust/horizon-issuer
```

And safely delete the old issuers.