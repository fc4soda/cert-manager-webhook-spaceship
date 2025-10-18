package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"net/http"
	"net/url"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
)

var (
	GroupName = os.Getenv("GROUP_NAME")
	customTtl = 3600
)

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	var ctx = context.Background()
	// This will register our custom DNS provider with the webhook serving
	// library, making it available as an API under the provided GroupName.
	// You can register multiple DNS provider implementations with a single
	// webhook, where the Name() method will be used to disambiguate between
	// the different implementations.
	cmd.RunWebhookServer(GroupName,
		&spaceshipDNSProviderSolver{ctx: ctx},
	)
}

// spaceshipDNSProviderSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// To do so, it must implement the `github.com/jetstack/cert-manager/pkg/acme/webhook.Solver`
// interface.
type spaceshipDNSProviderSolver struct {
	// If a Kubernetes 'clientset' is needed, you must:
	// 1. uncomment the additional `client` field in this structure below
	// 2. uncomment the "k8s.io/client-go/kubernetes" import at the top of the file
	// 3. uncomment the relevant code in the Initialize method below
	// 4. ensure your webhook's service account has the required RBAC role
	//    assigned to it for interacting with the Kubernetes APIs you need.
	client *kubernetes.Clientset
	ctx    context.Context
}

// spaceshipDNSProviderConfig is a structure that is used to decode into when
// solving a DNS01 challenge.
// This information is provided by cert-manager, and may be a reference to
// additional configuration that's needed to solve the challenge for this
// particular certificate or issuer.
// This typically includes references to Secret resources containing DNS
// provider credentials, in cases where a 'multi-tenant' DNS solver is being
// created.
// If you do *not* require per-issuer or per-certificate configuration to be
// provided to your webhook, you can skip decoding altogether in favour of
// using CLI flags or similar to provide configuration.
// You should not include sensitive information here. If credentials need to
// be used by your provider here, you should reference a Kubernetes Secret
// resource and fetch these credentials using a Kubernetes clientset.
type spaceshipDNSProviderConfig struct {
	// Change the two fields below according to the format of the configuration
	// to be decoded.
	// These fields will be set by users in the
	// `issuer.spec.acme.dns01.providers.webhook.config` field.
	Username     string                   `json:"username"`
	ApiKeyRef    corev1.SecretKeySelector `json:"apikey"`
	ApiSecretRef corev1.SecretKeySelector `json:"apisecret"`
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (c *spaceshipDNSProviderSolver) Name() string {
	return "spaceship"
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (c *spaceshipDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	domainName := extractDomainName(c.ctx, ch.ResolvedZone)
	recordName := extractRecordName(ch.ResolvedFQDN, ch.ResolvedZone)

	nc, err := c.spaceshipAPIClient(ch)
	if err != nil {
		return err
	}

	fmt.Printf("Presenting record for %s (%s, %s)\n", ch.ResolvedFQDN, recordName, domainName)

	err = nc.AddRecord(c.ctx, domainName, Record{
		Type:  "TXT",
		Name:  recordName,
		Value: ch.Key,
		TTL:   customTtl,
	})

	if err != nil {
		fmt.Printf("Error: %+v\n", err)
	}
	return err
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (c *spaceshipDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	domainName := extractDomainName(c.ctx, ch.ResolvedZone)
	recordName := extractRecordName(ch.ResolvedFQDN, ch.ResolvedZone)

	nc, err := c.spaceshipAPIClient(ch)
	if err != nil {
		return err
	}

	fmt.Printf("Cleaning up record for %s (%s)\n", ch.ResolvedFQDN, domainName)

	record := Record{
		Type: "TXT",
		Name: recordName,
	}

	return nc.DeleteRecord(c.ctx, domainName, record)
}

// Initialize will be called when the webhook first starts.
// This method can be used to instantiate the webhook, i.e. initialising
// connections or warming up caches.
// Typically, the kubeClientConfig parameter is used to build a Kubernetes
// client that can be used to fetch resources from the Kubernetes API, e.g.
// Secret resources containing credentials used to authenticate with DNS
// provider accounts.
// The stopCh can be used to handle early termination of the webhook, in cases
// where a SIGTERM or similar signal is sent to the webhook process.
func (c *spaceshipDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	c.client = cl

	return nil
}

// Create a name.com API client using a secret token
func (c *spaceshipDNSProviderSolver) spaceshipAPIClient(ch *v1alpha1.ChallengeRequest) (*Client, error) {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return nil, err
	}

	err = c.validate(&cfg, ch.AllowAmbientCredentials)
	if err != nil {
		return nil, err
	}

	apiKey, apiSecret, err := c.secret(cfg.ApiKeyRef, cfg.ApiSecretRef, ch.ResourceNamespace)
	if err != nil {
		return nil, err
	}

	nc, err := NewClient(apiKey, apiSecret)
	if err != nil {
		return nil, err
	}

	return nc, nil
}

// Validate config
func (c *spaceshipDNSProviderSolver) validate(cfg *spaceshipDNSProviderConfig, allowAmbientCredentials bool) error {
	if allowAmbientCredentials {
		// When allowAmbientCredentials is true, OVH client can load missing config
		// values from the environment variables and the ovh.conf files.
		return nil
	}
	if cfg.Username == "" {
		return errors.New("no Spaceship.com username provided in config")
	}
	if cfg.ApiKeyRef.Name == "" {
		return errors.New("no Spaceship.com API key provided in config")
	}
	if cfg.ApiKeyRef.Name == "" {
		return errors.New("no Spaceship.com API secret provided in config")
	}
	return nil
}

// Fetch the API token from secrets
func (c *spaceshipDNSProviderSolver) secret(keyRef, secretRef corev1.SecretKeySelector, namespace string) (key string, secret string, err error) {
	if keyRef.Name == "" {
		return
	}
	if secretRef.Name == "" {
		return
	}

	key, err = getSecretValue(c.client, namespace, keyRef)
	if err != nil {
		return
	}
	secret, err = getSecretValue(c.client, namespace, secretRef)
	if err != nil {
		return
	}

	return
}

func getSecretValue(client *kubernetes.Clientset, namespace string, ref corev1.SecretKeySelector) (string, error) {
	secret, err := client.CoreV1().Secrets(namespace).Get(context.TODO(), ref.Name, metav1.GetOptions{})
	if err != nil {
		return "", err
	}

	value := secret.Data[ref.Key]
	return string(value), nil
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func loadConfig(cfgJSON *apiextensionsv1.JSON) (spaceshipDNSProviderConfig, error) {
	cfg := spaceshipDNSProviderConfig{}

	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}
	return cfg, nil
}

func extractRecordName(fqdn, domain string) string {
	name := util.UnFqdn(fqdn)
	if idx := strings.Index(name, "."+util.UnFqdn(domain)); idx != -1 {
		return name[:idx]
	}
	return name
}

func extractDomainName(ctx context.Context, zone string) string {
	authZone, err := util.FindZoneByFqdn(ctx, zone, util.RecursiveNameservers)
	if err != nil {
		fmt.Printf("could not get zone by fqdn %v", err)
		return zone
	}
	return util.UnFqdn(authZone)
}

// ----------------------------------
const defaultBaseURL = "https://spaceship.dev/api/v1/"

// github.com/go-acme/lego/v4/providers/dns/spaceship/internal
// Client the Spaceship API client.
type Client struct {
	apiKey    string
	apiSecret string

	baseURL    *url.URL
	HTTPClient *http.Client
}

type Record struct {
	Type       string `json:"type,omitempty"`
	Name       string `json:"name,omitempty"`
	Value      string `json:"value,omitempty"`
	Address    string `json:"address,omitempty"`
	Nameserver string `json:"nameserver,omitempty"`
	AliasName  string `json:"aliasName,omitempty"`
	Pointer    string `json:"pointer,omitempty"`
	CName      string `json:"cname,omitempty"`
	Exchange   string `json:"exchange,omitempty"`
	TTL        int    `json:"ttl,omitempty"`
}

type Foo struct {
	Force bool     `json:"force,omitempty"`
	Items []Record `json:"items,omitempty"`
}

func newJSONRequest(ctx context.Context, method string, endpoint *url.URL, payload any) (*http.Request, error) {
	buf := new(bytes.Buffer)

	if payload != nil {
		err := json.NewEncoder(buf).Encode(payload)
		if err != nil {
			return nil, fmt.Errorf("failed to create request JSON body: %w", err)
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, endpoint.String(), buf)
	if err != nil {
		return nil, fmt.Errorf("unable to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")

	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	return req, nil
}

func (c *Client) do(req *http.Request, result any) error {
	req.Header.Add("X-Api-Secret", c.apiSecret)
	req.Header.Add("X-Api-Key", c.apiKey)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode/100 != 2 {
		return parseError(req, resp)
	}

	if result == nil {
		return nil
	}

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return NewReadResponseError(req, resp.StatusCode, err)
	}

	err = json.Unmarshal(raw, result)
	if err != nil {
		return NewUnmarshalError(req, resp.StatusCode, raw, err)
	}

	return nil
}

func parseError(req *http.Request, resp *http.Response) error {
	raw, _ := io.ReadAll(resp.Body)

	var errAPI APIError
	err := json.Unmarshal(raw, &errAPI)
	if err != nil {
		return fmt.Errorf("err: %v, respStatusCode: %v, respBody: %v", err.Error(), resp.StatusCode, raw)
	}

	return &errAPI
}

type APIError struct {
	Detail string `json:"detail"`
	Data   []struct {
		Field   string `json:"field"`
		Details string `json:"details"`
	} `json:"data"`
}

func (a *APIError) Error() string {
	msg := []string{a.Detail}

	for _, datum := range a.Data {
		msg = append(msg, fmt.Sprintf("%s: %s", datum.Field, datum.Details))
	}

	return strings.Join(msg, ", ")
}

// ReadResponseError use with `io.ReadAll` when reading response body.
type ReadResponseError struct {
	req        *http.Request
	StatusCode int
	err        error
}

// NewReadResponseError creates a new ReadResponseError.
func NewReadResponseError(req *http.Request, statusCode int, err error) *ReadResponseError {
	return &ReadResponseError{req: req, StatusCode: statusCode, err: err}
}

func (r ReadResponseError) Error() string {
	msg := "unable to read response body:"
	msg += fmt.Sprintf(" [request: %s %s]", r.req.Method, r.req.URL)
	msg += fmt.Sprintf(" [status code: %d]", r.StatusCode)

	if r.err == nil {
		return msg
	}

	return msg + fmt.Sprintf(" error: %v", r.err)
}

func (r ReadResponseError) Unwrap() error {
	return r.err
}

// UnmarshalError uses with `json.Unmarshal` or `xml.Unmarshal` when reading response body.
type UnmarshalError struct {
	req        *http.Request
	StatusCode int
	Body       []byte
	err        error
}

// NewUnmarshalError creates a new UnmarshalError.
func NewUnmarshalError(req *http.Request, statusCode int, body []byte, err error) *UnmarshalError {
	return &UnmarshalError{req: req, StatusCode: statusCode, Body: bytes.TrimSpace(body), err: err}
}

func (u UnmarshalError) Error() string {
	msg := "unable to unmarshal response:"
	msg += fmt.Sprintf(" [request: %s %s]", u.req.Method, u.req.URL)
	msg += fmt.Sprintf(" [status code: %d] body: %s", u.StatusCode, string(u.Body))

	if u.err == nil {
		return msg
	}

	return msg + fmt.Sprintf(" error: %v", u.err)
}

func (u UnmarshalError) Unwrap() error {
	return u.err
}

//-----------------

// NewClient creates a new Client.
func NewClient(apiKey, apiSecret string) (*Client, error) {
	if apiKey == "" || apiSecret == "" {
		return nil, errors.New("credentials missing")
	}

	baseURL, _ := url.Parse(defaultBaseURL)

	return &Client{
		apiKey:     apiKey,
		apiSecret:  apiSecret,
		baseURL:    baseURL,
		HTTPClient: &http.Client{Timeout: 10 * time.Second},
	}, nil
}

func (c *Client) AddRecord(ctx context.Context, domain string, record Record) error {
	endpoint := c.baseURL.JoinPath("dns", "records", domain)

	req, err := newJSONRequest(ctx, http.MethodPut, endpoint, Foo{Items: []Record{record}})
	if err != nil {
		return err
	}

	err = c.do(req, nil)
	if err != nil {
		return err
	}

	return nil
}

func (c *Client) DeleteRecord(ctx context.Context, domain string, record Record) error {
	endpoint := c.baseURL.JoinPath("dns", "records", domain)

	req, err := newJSONRequest(ctx, http.MethodDelete, endpoint, []Record{record})
	if err != nil {
		return err
	}

	err = c.do(req, nil)
	if err != nil {
		return err
	}

	return nil
}
