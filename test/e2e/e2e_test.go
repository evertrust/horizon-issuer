//go:build e2e
// +build e2e

/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package e2e

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/evertrust/horizon-issuer/test/utils"
)

// namespace where the project is deployed in
const namespace = "horizon-issuer-system"

// serviceAccountName created for the project
const serviceAccountName = "horizon-issuer-controller-manager"

// metricsServiceName is the name of the metrics service of the project
const metricsServiceName = "horizon-issuer-controller-manager-metrics-service"

// metricsRoleBindingName is the name of the RBAC that will be created to allow get the metrics data
const metricsRoleBindingName = "horizon-issuer-metrics-binding"

var _ = Describe("Manager", Ordered, func() {
	var controllerPodName string
	expectedAnnotations := map[string]string{
		"horizon.evertrust.io/owner":              "administrator",
		"horizon.evertrust.io/team":               "rocket",
		"horizon.evertrust.io/contact-email":      "user@rocket.com",
		"horizon.evertrust.io/labels.environment": "staging",
	}

	// Before running the tests, set up the environment by creating the namespace,
	// enforce the restricted security policy to the namespace, installing CRDs,
	// and deploying the controller.
	BeforeAll(func() {
		By("creating manager namespace")
		cmd := exec.Command("kubectl", "create", "ns", namespace)
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to create namespace")

		By("labeling the namespace to enforce the restricted security policy")
		cmd = exec.Command("kubectl", "label", "--overwrite", "ns", namespace,
			"pod-security.kubernetes.io/enforce=restricted")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to label namespace with restricted policy")

		By("deploying the controller-manager")
		cmd = exec.Command("kubectl", "apply", "-k", "config/default")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to deploy the controller-manager")
	})

	// After all tests have been executed, clean up by undeploying the controller, uninstalling CRDs,
	// and deleting the namespace.
	AfterAll(func() {
		if skipCleanup {
			return
		}

		By("cleaning up the curl pod for metrics")
		cmd := exec.Command("kubectl", "delete", "pod", "curl-metrics", "-n", namespace)
		_, _ = utils.Run(cmd)

		By("cleaning up the cluster role binding for metrics")
		cmd = exec.Command("kubectl", "delete", "clusterrolebinding", metricsRoleBindingName)
		_, _ = utils.Run(cmd)

		By("undeploying the controller-manager")
		cmd = exec.Command("kubectl", "delete", "-k", "config/default")
		_, _ = utils.Run(cmd)

		By("removing manager namespace")
		cmd = exec.Command("kubectl", "delete", "ns", namespace)
		_, _ = utils.Run(cmd)
	})

	// After each test, check for failures and collect logs, events,
	// and pod descriptions for debugging.
	AfterEach(func() {
		specReport := CurrentSpecReport()
		if specReport.Failed() {
			By("Fetching controller manager pod logs")
			cmd := exec.Command("kubectl", "logs", controllerPodName, "-n", namespace)
			controllerLogs, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Controller logs:\n %s", controllerLogs)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get Controller logs: %s", err)
			}

			By("Fetching Horizon pod logs")
			cmd = exec.Command("kubectl", "logs", "-l", "app.kubernetes.io/name=horizon", "-n", "horizon")
			horizonLogs, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Horizon logs:\n %s", horizonLogs)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get Horizon logs: %s", err)
			}

			By("Fetching Kubernetes events")
			cmd = exec.Command("kubectl", "get", "events", "-n", namespace, "--sort-by=.lastTimestamp")
			eventsOutput, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Kubernetes events:\n%s", eventsOutput)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get Kubernetes events: %s", err)
			}

			By("Fetching curl-metrics logs")
			cmd = exec.Command("kubectl", "logs", "curl-metrics", "-n", namespace, "--since-time", specReport.StartTime.Format(time.RFC3339))
			metricsOutput, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Metrics logs:\n %s", metricsOutput)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get curl-metrics logs: %s", err)
			}

			By("Fetching controller manager pod description")
			cmd = exec.Command("kubectl", "describe", "pod", controllerPodName, "-n", namespace)
			podDescription, err := utils.Run(cmd)
			if err == nil {
				fmt.Println("Pod description:\n", podDescription)
			} else {
				fmt.Println("Failed to describe controller pod")
			}
		}
	})

	SetDefaultEventuallyTimeout(2 * time.Minute)
	SetDefaultEventuallyPollingInterval(time.Second)

	Context("Manager", func() {
		It("should run successfully", func() {
			By("validating that the controller-manager pod is running as expected")
			verifyControllerUp := func(g Gomega) {
				// Get the name of the controller-manager pod
				cmd := exec.Command("kubectl", "get",
					"pods", "-l", "control-plane=controller-manager",
					"-o", "go-template={{ range .items }}"+
						"{{ if not .metadata.deletionTimestamp }}"+
						"{{ .metadata.name }}"+
						"{{ \"\\n\" }}{{ end }}{{ end }}",
					"-n", namespace,
				)

				podOutput, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to retrieve controller-manager pod information")
				podNames := utils.GetNonEmptyLines(podOutput)
				g.Expect(podNames).To(HaveLen(1), "expected 1 controller pod running")
				controllerPodName = podNames[0]
				g.Expect(controllerPodName).To(ContainSubstring("controller-manager"))

				// Validate the pod's status
				cmd = exec.Command("kubectl", "get",
					"pods", controllerPodName, "-o", "jsonpath={.status.phase}",
					"-n", namespace,
				)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Running"), "Incorrect controller-manager pod status")
			}
			Eventually(verifyControllerUp).Should(Succeed())
		})

		It("should ensure the metrics endpoint is serving metrics", func() {
			By("creating a ClusterRoleBinding for the service account to allow access to metrics")
			cmd := exec.Command("kubectl", "create", "clusterrolebinding", metricsRoleBindingName,
				"--clusterrole=horizon-issuer-metrics-reader",
				fmt.Sprintf("--serviceaccount=%s:%s", namespace, serviceAccountName),
			)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create ClusterRoleBinding")

			By("validating that the metrics service is available")
			cmd = exec.Command("kubectl", "get", "service", metricsServiceName, "-n", namespace)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Metrics service should exist")

			By("getting the service account token")
			token, err := serviceAccountToken()
			Expect(err).NotTo(HaveOccurred())
			Expect(token).NotTo(BeEmpty())

			By("ensuring the controller pod is ready")
			verifyControllerPodReady := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pod", controllerPodName, "-n", namespace,
					"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("True"), "Controller pod not ready")
			}
			Eventually(verifyControllerPodReady, 3*time.Minute, time.Second).Should(Succeed())

			By("verifying that the controller manager is serving the metrics server")
			verifyMetricsServerStarted := func(g Gomega) {
				cmd := exec.Command("kubectl", "logs", controllerPodName, "-n", namespace)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring("Serving metrics server"),
					"Metrics server not yet started")
			}
			Eventually(verifyMetricsServerStarted, 3*time.Minute, time.Second).Should(Succeed())

			// +kubebuilder:scaffold:e2e-metrics-webhooks-readiness

			By("creating the curl-metrics pod to access the metrics endpoint")
			cmd = exec.Command("kubectl", "run", "curl-metrics", "--restart=Never",
				"--namespace", namespace,
				"--image=curlimages/curl:latest",
				"--overrides",
				fmt.Sprintf(`{
					"spec": {
						"containers": [{
							"name": "curl",
							"image": "curlimages/curl:latest",
							"command": ["/bin/sh", "-c"],
							"args": ["curl -v -k -H 'Authorization: Bearer %s' https://%s.%s.svc.cluster.local:8443/metrics"],
							"securityContext": {
								"readOnlyRootFilesystem": true,
								"allowPrivilegeEscalation": false,
								"capabilities": {
									"drop": ["ALL"]
								},
								"runAsNonRoot": true,
								"runAsUser": 1000,
								"seccompProfile": {
									"type": "RuntimeDefault"
								}
							}
						}],
						"serviceAccountName": "%s"
					}
				}`, token, metricsServiceName, namespace, serviceAccountName))
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create curl-metrics pod")

			By("waiting for the curl-metrics pod to complete.")
			verifyCurlUp := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pods", "curl-metrics",
					"-o", "jsonpath={.status.phase}",
					"-n", namespace)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Succeeded"), "curl pod in wrong status")
			}
			Eventually(verifyCurlUp, 5*time.Minute).Should(Succeed())

			By("getting the metrics by checking curl-metrics logs")
			verifyMetricsAvailable := func(g Gomega) {
				metricsOutput, err := getMetricsOutput()
				g.Expect(err).NotTo(HaveOccurred(), "Failed to retrieve logs from curl pod")
				g.Expect(metricsOutput).NotTo(BeEmpty())
				g.Expect(metricsOutput).To(ContainSubstring("< HTTP/1.1 200 OK"))
			}
			Eventually(verifyMetricsAvailable, 2*time.Minute).Should(Succeed())
		})

		// +kubebuilder:scaffold:e2e-webhooks-checks
	})

	// Each issuer scenario runs twice, once per authentication mode. The manifests use the
	// static secret. authMode rewrites them for the service account run.
	for _, mode := range authModes {
		Context("with "+mode.name+" authentication", Ordered, func() {
			BeforeAll(func() {
				if !utils.HorizonVersionAtLeast(mode.minHorizonMajor, mode.minHorizonMinor) {
					Skip(fmt.Sprintf("%s authentication needs Horizon %d.%d or later",
						mode.name, mode.minHorizonMajor, mode.minHorizonMinor))
				}
				if mode.setup != nil {
					mode.setup()
				}
			})

			It("can reconcile issuer health status", func() {
				By("creating a valid clusterissuer")
				mode.apply("test/assets/manifests/valid-clusterissuer.yml")
				Eventually(
					utils.WaitForIssuerReady(mode.clusterIssuer("valid-clusterissuer"), ""),
					3*time.Minute, time.Second,
				).Should(Succeed())

				By("failing to create an issuer without proper TLS trust settings")
				mode.apply("test/assets/manifests/clusterissuer-without-ca.yml")
				Eventually(
					clusterIssuerNotReady(mode.clusterIssuer("clusterissuer-without-ca")),
					3*time.Minute, time.Second,
				).Should(Succeed())

				By("creating a clusterissuer with specific CA bundle")
				mode.apply("test/assets/manifests/clusterissuer-with-ca.yml")
				Eventually(
					utils.WaitForIssuerReady(mode.clusterIssuer("clusterissuer-with-ca"), ""),
					3*time.Minute, time.Second,
				).Should(Succeed())

				By("creating a clusterissuer with skipTlsVerify")
				mode.apply("test/assets/manifests/clusterissuer-with-skiptlsverify.yml")
				Eventually(
					utils.WaitForIssuerReady(mode.clusterIssuer("clusterissuer-with-skiptlsverify"), ""),
					3*time.Minute, time.Second,
				).Should(Succeed())
			})

			It("can issue a valid certificate", func() {
				mode.apply("test/assets/manifests/valid-certificate.yml")
				Eventually(
					utils.WaitForCertificateReady(mode.resource("valid-certificate")),
					3*time.Minute, time.Second,
				).Should(Succeed())

				By("ensuring the ca chain gets injected in the secret")
				verifyInjectedCAChain := func(g Gomega) {
					cmd := exec.Command("kubectl", "get", "secret", mode.resource("valid-certificate"), "-o", "json")
					output, err := utils.Run(cmd)
					g.Expect(err).NotTo(HaveOccurred())

					var secret struct {
						Data map[string]string `json:"data"`
					}
					g.Expect(json.Unmarshal([]byte(output), &secret)).To(Succeed())

					caBundleBase64, ok := secret.Data["ca.crt"]
					g.Expect(ok).To(BeTrue(), "expected ca.crt in secret")
					tlsChainBase64, ok := secret.Data["tls.crt"]
					g.Expect(ok).To(BeTrue(), "expected tls.crt in secret")

					caBundle, err := base64.StdEncoding.DecodeString(caBundleBase64)
					g.Expect(err).NotTo(HaveOccurred())
					caBlock, _ := pem.Decode(caBundle)
					g.Expect(caBlock).NotTo(BeNil(), "ca.crt should be PEM encoded")
					g.Expect(caBlock.Type).To(Equal("CERTIFICATE"), "ca.crt should contain a certificate PEM")
					caCert, err := x509.ParseCertificate(caBlock.Bytes)
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(caCert.IsCA).To(BeTrue(), "ca.crt should be a CA certificate")

					tlsChain, err := base64.StdEncoding.DecodeString(tlsChainBase64)
					g.Expect(err).NotTo(HaveOccurred())
					var certs []*x509.Certificate
					for {
						var block *pem.Block
						block, tlsChain = pem.Decode(tlsChain)
						if block == nil {
							break
						}
						if block.Type != "CERTIFICATE" {
							continue
						}
						cert, parseErr := x509.ParseCertificate(block.Bytes)
						g.Expect(parseErr).NotTo(HaveOccurred())
						certs = append(certs, cert)
					}

					g.Expect(len(certs)).To(BeNumerically(">=", 2), "tls.crt should contain at least two certificates")
					hasIntermediate := false
					hasLeaf := false
					for _, cert := range certs {
						if cert.IsCA {
							hasIntermediate = true
							continue
						}
						hasLeaf = true
					}
					g.Expect(hasIntermediate).To(BeTrue(), "tls.crt should include an intermediate CA certificate")
					g.Expect(hasLeaf).To(BeTrue(), "tls.crt should include the leaf certificate")
				}
				Eventually(verifyInjectedCAChain, 2*time.Minute, 5*time.Second).Should(Succeed())
			})

			It("can issue a certificate from an ingress with metadata", func() {
				mode.apply("test/assets/manifests/ingress-with-metadata.yml")
				Eventually(
					utils.WaitForCertificateReady(mode.resource("ingress-with-metadata")),
					3*time.Minute, time.Second,
				).Should(Succeed())
				utils.ExpectCertificateRequestAnnotations(
					mode.resource("ingress-with-metadata")+"-1",
					expectedAnnotations)
			})

			It("can issue a certificate with metadata", func() {
				mode.apply("test/assets/manifests/certificate-with-metadata.yml")
				Eventually(
					utils.WaitForCertificateReady(mode.resource("certificate-with-metadata")),
					3*time.Minute, time.Second,
				).Should(Succeed())
				utils.ExpectCertificateRequestAnnotations(
					mode.resource("certificate-with-metadata")+"-1",
					expectedAnnotations)
			})

			It("honors an issuer's defaultTemplate", func() {
				mode.apply("test/assets/manifests/clusterissuer-with-defaulttemplate.yml")
				Eventually(
					utils.WaitForIssuerReady(mode.clusterIssuer("clusterissuer-with-defaulttemplate"), ""),
					3*time.Minute, time.Second,
				).Should(Succeed())
				mode.apply("test/assets/manifests/certificate-with-defaulttemplate.yml")
				Eventually(
					utils.WaitForCertificateReady(mode.resource("certificate-with-defaulttemplate")),
					3*time.Minute, time.Second,
				).Should(Succeed())
				utils.ExpectCertificateRequestAnnotations(
					mode.resource("certificate-with-defaulttemplate")+"-1",
					expectedAnnotations)
			})

			It("can override an issuer's defaultTemplate", func() {
				mode.apply("test/assets/manifests/certificate-with-defaulttemplate-override.yml")
				Eventually(
					utils.WaitForCertificateReady(mode.resource("certificate-with-defaulttemplate-override")),
					3*time.Minute, time.Second,
				).Should(Succeed())
				utils.ExpectCertificateRequestAnnotations(
					mode.resource("certificate-with-defaulttemplate-override")+"-1",
					map[string]string{
						"horizon.evertrust.io/owner":              "user",
						"horizon.evertrust.io/team":               "dx",
						"horizon.evertrust.io/contact-email":      "test@rocket.com",
						"horizon.evertrust.io/labels.environment": "prod",
					})
			})

			It("honors an issuer's overrideTemplate", func() {
				mode.apply("test/assets/manifests/clusterissuer-with-overridetemplate.yml")
				Eventually(
					utils.WaitForIssuerReady(mode.clusterIssuer("clusterissuer-with-overridetemplate"), ""),
					3*time.Minute, time.Second,
				).Should(Succeed())
				mode.apply("test/assets/manifests/certificate-with-overridetemplate.yml")
				Eventually(
					utils.WaitForCertificateReady(mode.resource("certificate-with-overridetemplate")),
					3*time.Minute, time.Second,
				).Should(Succeed())
				utils.ExpectCertificateRequestAnnotations(
					mode.resource("certificate-with-overridetemplate")+"-1",
					expectedAnnotations)
			})

			It("cannot override an issuer's overrideTemplate", func() {
				mode.apply("test/assets/manifests/certificate-with-overridetemplate-override.yml")
				Eventually(
					utils.WaitForCertificateReady(mode.resource("certificate-with-overridetemplate-override")),
					3*time.Minute, time.Second,
				).Should(Succeed())
				utils.ExpectCertificateRequestAnnotations(
					mode.resource("certificate-with-overridetemplate-override")+"-1",
					expectedAnnotations)
			})

			It("can renew a certificate", func() {
				By("issuing a initial certificate")
				mode.apply("test/assets/manifests/certificate-to-renew.yml")
				Eventually(
					utils.WaitForCertificateReady(mode.resource("certificate-to-renew")),
					3*time.Minute, time.Second,
				).Should(Succeed())

				By("manually triggering the renew of the certificate")
				patch := `{"status":{"conditions":[{"type":"Issuing","status":"True","reason":"ManuallyTriggered",` +
					`"message":"Certificate re-issuance manually triggered","observedGeneration":2}]}}`
				cmd := exec.Command("kubectl", "patch", "certificate", mode.resource("certificate-to-renew"),
					"--type=merge", "--subresource=status", "-p", patch)
				_, err := utils.Run(cmd)
				Expect(err).NotTo(HaveOccurred(), "Failed to trigger renewal")

				By("waiting for the certificate to be re-issued")
				Eventually(
					utils.WaitForCertificateRequestReady(mode.resource("certificate-to-renew")+"-2"),
					3*time.Minute, time.Second,
				).Should(Succeed())
			})

			// TODO: currently not implemented
			// It("can update a certificate", func() {
			// 	By("enrolling an initial certificate")
			// 	mode.apply("test/assets/manifests/certificate-to-update.yml")
			// 	Eventually(utils.WaitForCertificateReady(mode.resource("certificate-to-update")), 3*time.Minute, time.Second).Should(Succeed())
			// 	utils.ExpectCertificateRequestAnnotations(mode.resource("certificate-to-update")+"-1", expectedAnnotations)

			// 	By("updating the certificate metadata")
			// 	mode.apply("test/assets/manifests/certificate-updated.yml")
			// 	Eventually(utils.WaitForCertificateReady(mode.resource("certificate-to-update")), 3*time.Minute, time.Second).Should(Succeed())
			// 	utils.ExpectCertificateRequestAnnotations(mode.resource("certificate-to-update")+"-2", map[string]string{
			// 		"horizon.evertrust.io/owner":              "user",
			// 		"horizon.evertrust.io/team":               "dx",
			// 		"horizon.evertrust.io/contact-email":      "test@rocket.com",
			// 		"horizon.evertrust.io/labels.environment": "prod",
			// 	})
			// })

			It("can revoke a certificate", func() {
				By("creating an issuer that revokes certificates")
				mode.apply("test/assets/manifests/clusterissuer-with-revokecertificates.yml")
				Eventually(
					utils.WaitForIssuerReady(mode.clusterIssuer("clusterissuer-with-revokecertificates"), ""),
					3*time.Minute, time.Second,
				).Should(Succeed())

				By("issuing a certificate to revoke")
				mode.apply("test/assets/manifests/certificate-to-revoke.yml")
				Eventually(
					utils.WaitForCertificateReady(mode.resource("certificate-to-revoke")),
					3*time.Minute, time.Second,
				).Should(Succeed())

				By("revoking the certificate")
				cmd := exec.Command("kubectl", "delete", "certificates/"+mode.resource("certificate-to-revoke"))
				_, err := utils.Run(cmd)
				Expect(err).NotTo(HaveOccurred())

				By("ensuring the RevokedCertificate event has been recorded")
				issuerName := mode.resource("clusterissuer-with-revokecertificates")
				verifyRevokedEvent := func(g Gomega) {
					eventCmd := exec.Command("kubectl", "get", "events",
						"--all-namespaces",
						"--field-selector",
						"involvedObject.kind=ClusterIssuer,involvedObject.name="+issuerName+",reason=RevokedCertificate",
						"-o", "json",
					)
					eventOutput, cmdErr := utils.Run(eventCmd)
					g.Expect(cmdErr).NotTo(HaveOccurred())

					var events struct {
						Items []struct {
							Reason string `json:"reason"`
						} `json:"items"`
					}
					g.Expect(json.Unmarshal([]byte(eventOutput), &events)).To(Succeed())
					g.Expect(events.Items).NotTo(BeEmpty(),
						"RevokedCertificate event not found for ClusterIssuer %s", issuerName)
				}
				Eventually(verifyRevokedEvent, 2*time.Minute, 5*time.Second).Should(Succeed())
			})

			It("can use an outbound proxy", func() {
				By("deploying a proxy service")
				utils.ApplyManifest("test/assets/manifests/proxy.yml")
				verifyProxyPodReady := func(g Gomega) {
					cmd := exec.Command("kubectl", "get", "pod", "tinyproxy", "-n", "tinyproxy",
						"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
					output, err := utils.Run(cmd)
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(output).To(Equal("True"), "Proxy pod not ready")
				}
				Eventually(verifyProxyPodReady, 10*time.Minute, time.Second).Should(Succeed())

				By("creating a clusterissuer with proxy")
				mode.apply("test/assets/manifests/clusterissuer-with-proxy.yml")
				Eventually(
					utils.WaitForIssuerReady(mode.clusterIssuer("clusterissuer-with-proxy"), namespace),
					3*time.Minute, time.Second,
				).Should(Succeed())

				By("ensuring the proxy pod received requests")
				cmd := exec.Command("kubectl", "exec", "tinyproxy", "-n", "tinyproxy", "--", "/bin/bash", "-c",
					"http_proxy=http://localhost:8888 wget --proxy on http://tinyproxy.stats -O - -q | sed -n '/Number of requests/{n;s/.*<td>\\([0-9]\\+\\)<\\/td>.*/\\1/p}'",
				)
				output, err := utils.Run(cmd)
				Expect(err).NotTo(HaveOccurred(), "Failed to get tinyproxy stats")
				requestCount, err := strconv.Atoi(strings.TrimSpace(output))
				Expect(err).NotTo(HaveOccurred(), "Failed to get tinyproxy stats")
				Expect(requestCount).To(BeNumerically(">", 0))
			})

			for _, extra := range mode.extraSpecs {
				It(extra.name, extra.body)
			}
		})
	}
})

// authMode is one way for issuers to authenticate against Horizon. The scenarios run once per mode.
type authMode struct {
	name string
	// suffix goes on every test resource name so both runs can share the cluster.
	suffix string
	// The mode is skipped when Horizon is older than minHorizonMajor.minHorizonMinor.
	minHorizonMajor, minHorizonMinor int
	// rewriteAuth swaps the static secret reference of a manifest for this mode's auth block.
	rewriteAuth func(manifest string) string
	// setup runs once before the scenarios, for example to declare the service account in Horizon.
	setup func()
	// extraSpecs only make sense for this mode. They run after the shared scenarios.
	extraSpecs []extraSpec
}

type extraSpec struct {
	name string
	body func()
}

// resource returns the name a test resource gets in this mode.
func (m authMode) resource(base string) string {
	return base + m.suffix
}

// clusterIssuer returns the kubectl reference of a ClusterIssuer in this mode.
func (m authMode) clusterIssuer(base string) string {
	return "clusterissuers.horizon.evertrust.io/" + m.resource(base)
}

// apply reads a manifest written for the static secret, rewrites it for this mode and applies it.
func (m authMode) apply(manifestPath string) {
	content, err := os.ReadFile(manifestPath)
	Expect(err).NotTo(HaveOccurred(), "Failed to read manifest %s", manifestPath)
	manifest := suffixTestResources(string(content), m.suffix)
	if m.rewriteAuth != nil {
		manifest = m.rewriteAuth(manifest)
	}
	utils.ApplyManifestContent(manifest)
}

// testResourceLine matches the YAML lines that name a test resource: metadata.name, secretName,
// commonName, issuerRef.name, the cert-manager annotations and TLS hosts. It only matches values
// named after a manifest (valid-, certificate-, clusterissuer-, ingress-), so Secrets, Services
// and namespaces keep their names.
var testResourceLine = regexp.MustCompile(
	`^(\s*(?:(?:name|secretName|commonName|cert-manager\.io/issuer|cert-manager\.io/common-name): *|- ))` +
		`((?:valid|certificate|clusterissuer|ingress)-[A-Za-z0-9-]*?)(\.org)?\s*$`)

// suffixTestResources appends suffix to every test resource name found in the manifest.
func suffixTestResources(manifest, suffix string) string {
	if suffix == "" {
		return manifest
	}
	lines := strings.Split(manifest, "\n")
	for i, line := range lines {
		lines[i] = testResourceLine.ReplaceAllString(line, "${1}${2}"+suffix+"${3}")
	}
	return strings.Join(lines, "\n")
}

const staticSecretAuth = "  authSecretName: horizon-credentials\n"

// serviceAccountAuth replaces the static secret line in service account mode. The controller
// requests a token for its own ServiceAccount through the TokenRequest API.
const serviceAccountAuth = `  serviceAccount:
    name: horizon-issuer-tokenrequest
    serviceAccountRef:
      name: ` + serviceAccountName + "\n"

var authModes = []authMode{
	{
		name:            "static secret",
		minHorizonMajor: 2,
		minHorizonMinor: 8,
	},
	{
		name:            "JWKS service account",
		suffix:          "-sa",
		minHorizonMajor: 2,
		minHorizonMinor: 10,
		rewriteAuth: func(manifest string) string {
			return strings.ReplaceAll(manifest, staticSecretAuth, serviceAccountAuth)
		},
		setup: declareHorizonServiceAccounts,
		extraSpecs: []extraSpec{
			{
				name: "rejects a token whose audience fails the validation rules",
				body: func() {
					utils.ApplyManifest("test/assets/manifests/clusterissuer-with-serviceaccount-badaudience.yml")
					Eventually(
						clusterIssuerNotReady("clusterissuers.horizon.evertrust.io/clusterissuer-with-serviceaccount-badaudience"),
						3*time.Minute, time.Second,
					).Should(Succeed())
				},
			},
		},
	},
}

// clusterIssuerNotReady is for Eventually: it passes once the Ready condition is False.
func clusterIssuerNotReady(resource string) func(Gomega) {
	return func(g Gomega) {
		cmd := exec.Command("kubectl", "get", resource,
			"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
		output, err := utils.Run(cmd)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(output).To(Equal("False"), "%s is ready", resource)
	}
}

// declareHorizonServiceAccounts registers in Horizon the service account the tests
// authenticate with. It trusts the cluster JWKS and accepts tokens of the controller
// ServiceAccount only. The controller sets the issuer URL as audience by default, and the
// scenarios reach Horizon both over http (9000) and https (9443), so the audience rule
// checks the host rather than one exact URL. A foreign audience still fails it.
func declareHorizonServiceAccounts() {
	By("reading the JWKS the cluster signs service account tokens with")
	jwks, err := utils.ClusterJWKS()
	Expect(err).NotTo(HaveOccurred(), "Failed to read the cluster JWKS")

	By("copying the administrator's roles and permissions onto the service account")
	selfOutput, err := utils.HorizonAPI("GET", "/api/v1/security/principals/self", "")
	Expect(err).NotTo(HaveOccurred(), "Failed to read the administrator principal")
	var self struct {
		Roles       []string            `json:"roles"`
		Permissions []horizonPermission `json:"permissions"`
	}
	Expect(json.Unmarshal([]byte(selfOutput), &self)).To(Succeed())
	if self.Roles == nil {
		self.Roles = []string{}
	}
	if self.Permissions == nil {
		self.Permissions = []horizonPermission{}
	}

	serviceAccount := horizonServiceAccount{
		Name:        "horizon-issuer-tokenrequest",
		TrustConfig: horizonTrustConfig{Type: "static_jwks", Jwks: jwks},
		ValidationRules: []string{
			`{{iss}} contains "kubernetes.default.svc"`,
			fmt.Sprintf(`{{"kubernetes.io".namespace}} equals "%s"`, namespace),
			fmt.Sprintf(`{{"kubernetes.io".serviceaccount.name}} equals "%s"`, serviceAccountName),
			`{{aud.1}} contains "://horizon.horizon.svc.cluster.local:"`,
		},
		Roles:       self.Roles,
		Permissions: self.Permissions,
	}

	By("declaring the service account in Horizon")
	payload, err := json.Marshal(serviceAccount)
	Expect(err).NotTo(HaveOccurred())
	// A previous run with HORIZON_ISSUER_E2E_SKIP_CLEANUP may have left it behind.
	_, _ = utils.HorizonAPI("DELETE", "/api/v1/security/service-accounts/"+serviceAccount.Name, "")
	_, err = utils.HorizonAPI("POST", "/api/v1/security/service-accounts", string(payload))
	Expect(err).NotTo(HaveOccurred(), "Failed to create service account %s", serviceAccount.Name)
}

// horizonServiceAccount is the payload of POST /api/v1/security/service-accounts.
type horizonServiceAccount struct {
	Name            string              `json:"name"`
	TrustConfig     horizonTrustConfig  `json:"trustConfig"`
	ValidationRules []string            `json:"validationRules"`
	Roles           []string            `json:"roles"`
	Permissions     []horizonPermission `json:"permissions"`
}

type horizonTrustConfig struct {
	Type string `json:"type"`
	Jwks string `json:"jwks"`
}

type horizonPermission struct {
	Value  string  `json:"value"`
	Filter *string `json:"filter,omitempty"`
}

// serviceAccountToken returns a token for the specified service account in the given namespace.
// It uses the Kubernetes TokenRequest API to generate a token by directly sending a request
// and parsing the resulting token from the API response.
func serviceAccountToken() (string, error) {
	const tokenRequestRawString = `{
		"apiVersion": "authentication.k8s.io/v1",
		"kind": "TokenRequest"
	}`

	// Temporary file to store the token request
	secretName := fmt.Sprintf("%s-token-request", serviceAccountName)
	tokenRequestFile := filepath.Join("/tmp", secretName)
	err := os.WriteFile(tokenRequestFile, []byte(tokenRequestRawString), os.FileMode(0o644))
	if err != nil {
		return "", err
	}

	var out string
	verifyTokenCreation := func(g Gomega) {
		// Execute kubectl command to create the token
		cmd := exec.Command("kubectl", "create", "--raw", fmt.Sprintf(
			"/api/v1/namespaces/%s/serviceaccounts/%s/token",
			namespace,
			serviceAccountName,
		), "-f", tokenRequestFile)

		output, err := cmd.CombinedOutput()
		g.Expect(err).NotTo(HaveOccurred())

		// Parse the JSON output to extract the token
		var token tokenRequest
		err = json.Unmarshal(output, &token)
		g.Expect(err).NotTo(HaveOccurred())

		out = token.Status.Token
	}
	Eventually(verifyTokenCreation).Should(Succeed())

	return out, err
}

// getMetricsOutput retrieves and returns the logs from the curl pod used to access the metrics endpoint.
func getMetricsOutput() (string, error) {
	By("getting the curl-metrics logs")
	cmd := exec.Command("kubectl", "logs", "curl-metrics", "-n", namespace)
	return utils.Run(cmd)
}

// tokenRequest is a simplified representation of the Kubernetes TokenRequest API response,
// containing only the token field that we need to extract.
type tokenRequest struct {
	Status struct {
		Token string `json:"token"`
	} `json:"status"`
}
