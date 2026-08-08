package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
	libdnsspaceship "github.com/fc4soda/libdns-spaceship"
	"github.com/libdns/libdns"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var (
	GroupName = os.Getenv("GROUP_NAME")
)

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	cmd.RunWebhookServer(GroupName, &spaceshipDNSProviderSolver{})
}

// spaceshipDNSProviderSolver 实现 cert-manager webhook 接口
type spaceshipDNSProviderSolver struct {
	client *kubernetes.Clientset
}

// spaceshipDNSProviderConfig 定义用户提供的配置结构
type spaceshipDNSProviderConfig struct {
	Username     string                   `json:"username"`
	ApiKeyRef    corev1.SecretKeySelector `json:"apikey"`
	ApiSecretRef corev1.SecretKeySelector `json:"apisecret"`
	BaseURL      string                   `json:"baseURL,omitempty"`
}

// Name 返回 solver 名称
func (c *spaceshipDNSProviderSolver) Name() string {
	return "spaceship"
}

// Present 创建 DNS TXT 记录
func (c *spaceshipDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	provider, err := c.newProvider(&cfg, ch.ResourceNamespace)
	if err != nil {
		return err
	}

	// 使用已验证的域名提取函数
	domainName := extractDomainName(context.TODO(), ch.ResolvedZone)  // 返回裸域名，如 "example.com"
	recordName := extractRecordName(ch.ResolvedFQDN, ch.ResolvedZone) // 返回相对名，如 "_acme-challenge"

	// 构建 TXT 记录，Name 用相对名
	record := libdns.TXT{
		Name: recordName,
		TTL:  60 * time.Second,
		Text: ch.Key, // 改为 Text
	}

	fmt.Printf("Presenting TXT record for %s (relative: %s, zone: %s)\n", ch.ResolvedFQDN, recordName, domainName)

	_, err = provider.AppendRecords(context.TODO(), domainName, []libdns.Record{record})
	if err != nil {
		fmt.Printf("Error presenting record: %+v\n", err)
		return err
	}

	return nil
}

// CleanUp 删除 DNS TXT 记录
func (c *spaceshipDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	provider, err := c.newProvider(&cfg, ch.ResourceNamespace)
	if err != nil {
		return err
	}

	domainName := extractDomainName(context.TODO(), ch.ResolvedZone)
	recordName := extractRecordName(ch.ResolvedFQDN, ch.ResolvedZone)

	// 获取所有记录
	records, err := provider.GetRecords(context.TODO(), domainName)
	if err != nil {
		return err
	}

	var toDelete []libdns.Record
	targetFQDN := ch.ResolvedFQDN
	// 记录日志，方便调试
	fmt.Printf("Looking for TXT record with name %s and key %s\n", targetFQDN, ch.Key)
	for _, r := range records {
		rr := r.RR()
		// 打印每条记录的实际信息（调试用）
		fmt.Printf("DEBUG: Record Name=%q, Type=%q, Data=%q\n", rr.Name, rr.Type, rr.Data)
		if rr.Type == "TXT" && rr.Name == recordName && rr.Data == ch.Key {
			toDelete = append(toDelete, r)
		}
	}

	if len(toDelete) == 0 {
		fmt.Printf("No matching TXT record found for %s\n", ch.ResolvedFQDN)
		return nil
	}

	fmt.Printf("Cleaning up TXT record for %s\n", ch.ResolvedFQDN)

	_, err = provider.DeleteRecords(context.TODO(), domainName, toDelete)
	if err != nil {
		fmt.Printf("Error cleaning up record: %+v\n", err)
		return err
	}

	return nil
}

// Initialize 初始化 webhook
func (c *spaceshipDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	c.client = cl
	return nil
}

// newProvider 创建 Spaceship provider 实例
func (c *spaceshipDNSProviderSolver) newProvider(cfg *spaceshipDNSProviderConfig, namespace string) (*libdnsspaceship.Provider, error) {
	apiKey, err := c.getSecretValue(namespace, cfg.ApiKeyRef)
	if err != nil {
		return nil, fmt.Errorf("failed to get API key: %w", err)
	}

	apiSecret, err := c.getSecretValue(namespace, cfg.ApiSecretRef)
	if err != nil {
		return nil, fmt.Errorf("failed to get API secret: %w", err)
	}

	// 创建 Provider
	provider := &libdnsspaceship.Provider{
		APIKey:    apiKey,
		APISecret: apiSecret,
		BaseURL:   "", // 可选，默认为 https://spaceship.dev/api
	}
	provider.SetLogLevel(libdnsspaceship.LogLevelDebug)

	// 如果用户指定了 BaseURL，则覆盖默认值
	if cfg.BaseURL != "" {
		provider.BaseURL = cfg.BaseURL
	}

	return provider, nil
}

// getSecretValue 从 Kubernetes Secret 获取值
func (c *spaceshipDNSProviderSolver) getSecretValue(namespace string, ref corev1.SecretKeySelector) (string, error) {
	if ref.Name == "" {
		return "", fmt.Errorf("secret name is required")
	}

	secret, err := c.client.CoreV1().Secrets(namespace).Get(context.TODO(), ref.Name, metav1.GetOptions{})
	if err != nil {
		return "", err
	}

	value, ok := secret.Data[ref.Key]
	if !ok {
		return "", fmt.Errorf("key %s not found in secret %s", ref.Key, ref.Name)
	}

	return string(value), nil
}

// loadConfig 解码 JSON 配置
func loadConfig(cfgJSON *apiextensionsv1.JSON) (spaceshipDNSProviderConfig, error) {
	cfg := spaceshipDNSProviderConfig{}

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
