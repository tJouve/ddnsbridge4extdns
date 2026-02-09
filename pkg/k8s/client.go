package k8s

import (
	"context"
	"fmt"
	"log"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/tJouve/ddnsbridge4extdns/pkg/update"
)

// Client manages Kubernetes DNSEndpoint resources
type Client struct {
	dynamicClient dynamic.Interface
	namespace     string
	gvr           schema.GroupVersionResource
	customLabels  map[string]string
}

// NewClient creates a new Kubernetes client
func NewClient(namespace string, customLabels map[string]string) (*Client, error) {
	config, err := getKubeConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get kubeconfig: %w", err)
	}

	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create dynamic client: %w", err)
	}

	// DNSEndpoint CRD from ExternalDNS
	gvr := schema.GroupVersionResource{
		Group:    "externaldns.k8s.io",
		Version:  "v1alpha1",
		Resource: "dnsendpoints",
	}

	if customLabels == nil {
		customLabels = map[string]string{}
	}

	return &Client{
		dynamicClient: dynamicClient,
		namespace:     namespace,
		gvr:           gvr,
		customLabels:  customLabels,
	}, nil
}

// ApplyUpdate applies a DNS update to Kubernetes as a DNSEndpoint resource
func (c *Client) ApplyUpdate(upd *update.DNSUpdate) error {
	ctx := context.Background()

	switch upd.Type {
	case update.UpdateTypeCreate, update.UpdateTypeUpdate:
		return c.createOrUpdateEndpoint(ctx, upd)
	case update.UpdateTypeDelete:
		return c.deleteEndpoint(ctx, upd)
	default:
		return fmt.Errorf("unsupported update type: %v", upd.Type)
	}
}

// createOrUpdateEndpoint creates or updates a DNSEndpoint resource
func (c *Client) createOrUpdateEndpoint(ctx context.Context, upd *update.DNSUpdate) error {
	hostname := upd.GetHostname()
	resourceName := sanitizeResourceName(hostname)

	recordType := "A"
	if upd.RecordType == 28 { // dns.TypeAAAA
		recordType = "AAAA"
	}

	// Build labels map with default labels
	labels := map[string]interface{}{
		"app.kubernetes.io/managed-by": "ddnsbridge4extdns",
		"ddns-zone":                    sanitizeLabel(upd.Zone),
	}

	// Add custom labels (user-defined labels take precedence)
	for k, v := range c.customLabels {
		labels[k] = v
	}

	endpoint := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "externaldns.k8s.io/v1alpha1",
			"kind":       "DNSEndpoint",
			"metadata": map[string]interface{}{
				"name":      resourceName,
				"namespace": c.namespace,
				"labels":    labels,
			},
			"spec": map[string]interface{}{
				"endpoints": []interface{}{
					map[string]interface{}{
						"dnsName":    upd.Name,
						"recordType": recordType,
						"recordTTL":  int64(upd.TTL),
						"targets": []interface{}{
							upd.IP.String(),
						},
					},
				},
			},
		},
	}

	// Try to get existing resource
	existing, err := c.dynamicClient.Resource(c.gvr).Namespace(c.namespace).Get(ctx, resourceName, metav1.GetOptions{})
	if err == nil {
		// Update existing resource
		endpoint.SetResourceVersion(existing.GetResourceVersion())
		_, err = c.dynamicClient.Resource(c.gvr).Namespace(c.namespace).Update(ctx, endpoint, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("failed to update DNSEndpoint: %w", err)
		}
		log.Printf("Successfully updated DNSEndpoint %s/%s", c.namespace, resourceName)
		return nil
	}

	// Create new resource
	_, err = c.dynamicClient.Resource(c.gvr).Namespace(c.namespace).Create(ctx, endpoint, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create DNSEndpoint: %w", err)
	}
	log.Printf("Successfully created DNSEndpoint %s/%s", c.namespace, resourceName)

	return nil
}

// deleteEndpoint deletes a DNSEndpoint resource
func (c *Client) deleteEndpoint(ctx context.Context, upd *update.DNSUpdate) error {
	hostname := upd.GetHostname()
	resourceName := sanitizeResourceName(hostname)

	err := c.dynamicClient.Resource(c.gvr).Namespace(c.namespace).Delete(ctx, resourceName, metav1.DeleteOptions{})
	if err != nil {
		// Ignore not found errors
		if !isNotFoundError(err) {
			return fmt.Errorf("failed to delete DNSEndpoint: %w", err)
		}
	} else {
		log.Printf("Successfully deleted DNSEndpoint %s/%s", c.namespace, resourceName)
	}

	return nil
}

// getKubeConfig returns the Kubernetes configuration
func getKubeConfig() (*rest.Config, error) {
	// Try in-cluster config first
	config, err := rest.InClusterConfig()
	if err == nil {
		return config, nil
	}

	// Fallback to the clientcmd deferred loader (this will pick up KUBECONFIG or defaults too)
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	configOverrides := &clientcmd.ConfigOverrides{}
	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)
	cfg, cfgErr := kubeConfig.ClientConfig()
	if cfgErr == nil {
		return cfg, nil
	}

	// Return aggregated error with a helpful message
	return nil, fmt.Errorf("no kubeconfig found (in-cluster, KUBECONFIG); last error: %w", cfgErr)
}

// sanitizeResourceName converts a hostname to a valid Kubernetes resource name
func sanitizeResourceName(hostname string) string {
	// Remove trailing dots and replace dots with hyphens
	name := hostname
	if len(name) > 0 && name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}
	// Replace dots and other invalid characters with hyphens
	name = dnsNameToK8sName(name)

	// Ensure it starts with alphanumeric
	if len(name) > 0 && !isAlphanumeric(rune(name[0])) {
		name = "dns-" + name
	}

	// Truncate to 253 characters (Kubernetes limit)
	if len(name) > 253 {
		name = name[:253]
	}

	return name
}

// sanitizeLabel converts a zone name to a valid Kubernetes label value
func sanitizeLabel(zone string) string {
	label := zone
	if len(label) > 0 && label[len(label)-1] == '.' {
		label = label[:len(label)-1]
	}
	label = dnsNameToK8sName(label)

	// Truncate to 63 characters (Kubernetes label limit)
	if len(label) > 63 {
		label = label[:63]
	}

	return label
}

// dnsNameToK8sName converts a DNS name to a valid Kubernetes name
func dnsNameToK8sName(name string) string {
	name = strings.ToLower(name)
	result := make([]rune, 0, len(name))
	for _, r := range name {
		if isAlphanumeric(r) || r == '-' {
			result = append(result, r)
		} else if r == '.' || r == '_' {
			result = append(result, '-')
		}
	}
	return string(result)
}

// isAlphanumeric checks if a rune is alphanumeric
func isAlphanumeric(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
}

// isNotFoundError checks if an error is a not found error
func isNotFoundError(err error) bool {
	return apierrors.IsNotFound(err)
}
