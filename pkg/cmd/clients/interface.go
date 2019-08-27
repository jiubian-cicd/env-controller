package clients

import (
	"github.com/jiubian-cicd/env-controller/pkg/helm"
	"io"

	"github.com/jiubian-cicd/env-controller/pkg/auth"
	"github.com/jiubian-cicd/env-controller/pkg/gits"
	"gopkg.in/AlecAivazis/survey.v1/terminal"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	// this is so that we load the auth plugins so we can connect to, say, GCP

	_ "k8s.io/client-go/plugin/pkg/client/auth"
)

// Factory is the interface defined for jx interactions via the cli
//go:generate pegomock generate github.com/jiubian-cicd/env-controller/pkg/cmd/clients Factory -o mocks/factory.go
type Factory interface {
	//
	// Constructors
	//

	//// WithBearerToken creates a factory from a k8s bearer token
	//WithBearerToken(token string) Factory
	//
	//// ImpersonateUser creates a factory with an impersonated users
	//ImpersonateUser(user string) Factory

	//
	// Configuration services
	//

	// CreateAuthConfigService creates a new authentication configuration service
	CreateAuthConfigService(fileName string, namespace string) (auth.ConfigService, error)
	//
	//// CreateJenkinsAuthConfigService creates a new Jenkins authentication configuration service
	//CreateJenkinsAuthConfigService(kubernetes.Interface, string, string) (auth.ConfigService, error)

	//// CreateChartmuseumAuthConfigService creates a new Chartmuseum authentication configuration service
	//CreateChartmuseumAuthConfigService(namespace string) (auth.ConfigService, error)
	//
	//// CreateIssueTrackerAuthConfigService creates a new issuer tracker configuration service
	//CreateIssueTrackerAuthConfigService(namespace string, secrets *corev1.SecretList) (auth.ConfigService, error)
	//
	//// CreateChatAuthConfigService creates a new chat configuration service
	//CreateChatAuthConfigService(namespace string, secrets *corev1.SecretList) (auth.ConfigService, error)
	//
	//// CreateAddonAuthConfigService creates a new addon auth configuration service
	//CreateAddonAuthConfigService(namespace string, secrets *corev1.SecretList) (auth.ConfigService, error)

	//
	// Generic clients
	//


	// CreateGitProvider creates a new Git provider
	CreateGitProvider(string, string, auth.ConfigService, string, bool, gits.Gitter, terminal.FileReader, terminal.FileWriter, io.Writer) (gits.GitProvider, error)


	// CreateHelm creates a new helm client
	CreateHelm(verbose bool, helmBinary string, noTiller bool, helmTemplate bool) helm.Helmer

	//
	// Kubernetes clients
	//

	// CreateKubeClient creates a new Kubernetes client
	CreateKubeClient() (kubernetes.Interface, string, error)

	// CreateKubeConfig creates the kubernetes configuration
	CreateKubeConfig() (*rest.Config, error)


	// CreateTable creates a new table
	//CreateTable(out io.Writer) table.Table

	// GetJenkinsURL returns the Jenkins URL
	//GetJenkinsURL(kubeClient kubernetes.Interface, ns string) (string, error)

	//// GetCustomJenkinsURL gets a custom jenkins App service URL
	//GetCustomJenkinsURL(kubeClient kubernetes.Interface, ns string, jenkinsServiceName string) (string, error)
	//
	//// SetBatch configures the batch modes
	//SetBatch(batch bool)
	//
	//// For tests only, assert that no actual network connections are being made.
	//SetOffline(offline bool)

	//IsInCluster indicates if the execution takes place within a Kubernetes cluster
	IsInCluster() bool

	// IsInCDPipeline indicates if the execution takes place within a CD pipeline
	//IsInCDPipeline() bool

	// AuthMergePipelineSecrets merges the current config with the pipeline secrets provided in k8s secrets
	//AuthMergePipelineSecrets(config *auth.AuthConfig, secrets *corev1.SecretList, kind string, isCDPipeline bool) error

	// SecretsLocation inidcates the location of the secrets
	//SecretsLocation() secrets.SecretsLocationKind

	// SetSecretsLocation configures the secrets location in memory. It will persist the secrets location in a
	// config map if the persist flag is active.
	//SetSecretsLocation(location secrets.SecretsLocationKind, persist bool) error

	// ResetSecretsLocation resets the location of the secrets
	//ResetSecretsLocation()
}
