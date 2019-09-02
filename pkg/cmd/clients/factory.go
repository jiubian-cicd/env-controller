package clients

import (
	"flag"
	"fmt"
	"github.com/jiubian-cicd/env-controller/pkg/log"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/jiubian-cicd/env-controller/pkg/gits"
	"github.com/jiubian-cicd/env-controller/pkg/helm"
	"github.com/jiubian-cicd/env-controller/pkg/kube"
	"github.com/jiubian-cicd/env-controller/pkg/table"
	"github.com/pkg/errors"
	"gopkg.in/AlecAivazis/survey.v1/terminal"

	"github.com/jiubian-cicd/env-controller/pkg/auth"

	"github.com/jiubian-cicd/env-controller/pkg/util"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	corev1 "k8s.io/api/core/v1"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"github.com/jiubian-cicd/env-controller/pkg/io/secrets"
)

type factory struct {
	Batch bool

	kubeConfig      kube.Kuber
	impersonateUser string
	bearerToken     string
	secretLocation  secrets.SecretLocation
	offline         bool
}

var _ Factory = (*factory)(nil)

// NewFactory creates a factory with the default Kubernetes resources defined
// if optionalClientConfig is nil, then flags will be bound to a new clientcmd.ClientConfig.
// if optionalClientConfig is not nil, then this factory will make use of it.
func NewFactory() Factory {
	f := &factory{}
	f.kubeConfig = kube.NewKubeConfig()
	return f
}

func (f *factory) SetBatch(batch bool) {
	f.Batch = batch
}

func (f *factory) SetOffline(offline bool) {
	f.offline = offline
}

// ImpersonateUser returns a new factory impersonating the given user
func (f *factory) ImpersonateUser(user string) Factory {
	copy := *f
	copy.impersonateUser = user
	return &copy
}

// WithBearerToken returns a new factory with bearer token
func (f *factory) WithBearerToken(token string) Factory {
	copy := *f
	copy.bearerToken = token
	return &copy
}


//func (f *factory) CreateJenkinsAuthConfigService(c kubernetes.Interface, ns string, jenkinsServiceName string) (auth.ConfigService, error) {
//	authConfigSvc, err := f.CreateAuthConfigService(auth.JenkinsAuthConfigFile, ns)
//
//	if jenkinsServiceName == "" {
//		jenkinsServiceName = kube.SecretJenkins
//	}
//
//	if err != nil {
//		return authConfigSvc, err
//	}
//	config, err := authConfigSvc.LoadConfig()
//	if err != nil {
//		return authConfigSvc, err
//	}
//
//	customJenkins := jenkinsServiceName != kube.SecretJenkins
//
//	if len(config.Servers) == 0 || customJenkins {
//		secretName := jenkinsServiceName
//		if customJenkins {
//			secretName = jenkinsServiceName + "-auth"
//		}
//		userAuth := auth.UserAuth{}
//
//		s, err := c.CoreV1().Secrets(ns).Get(secretName, metav1.GetOptions{})
//		if err != nil {
//			if !customJenkins {
//				return authConfigSvc, err
//			}
//		}
//		if s != nil {
//			userAuth.Username = string(s.Data[kube.JenkinsAdminUserField])
//			userAuth.ApiToken = string(s.Data[kube.JenkinsAdminApiToken])
//			userAuth.BearerToken = string(s.Data[kube.JenkinsBearTokenField])
//		}
//
//		if customJenkins {
//			s, err = c.CoreV1().Secrets(ns).Get(jenkinsServiceName, metav1.GetOptions{})
//			if err == nil {
//				if userAuth.Username == "" {
//					userAuth.Username = string(s.Data[kube.JenkinsAdminUserField])
//				}
//				userAuth.Password = string(s.Data[kube.JenkinsAdminPasswordField])
//			}
//		}
//
//		svcURL, err := services.FindServiceURL(c, ns, jenkinsServiceName)
//		if svcURL == "" {
//			return authConfigSvc, fmt.Errorf("unable to find external URL of service %s in namespace %s", jenkinsServiceName, ns)
//		}
//
//		u, err := url.Parse(svcURL)
//		if err != nil {
//			return authConfigSvc, err
//		}
//		if !userAuth.IsInvalid() || (customJenkins && userAuth.Password != "") {
//			if len(config.Servers) == 0 {
//				config.Servers = []*auth.AuthServer{
//					{
//						Name:  u.Host,
//						URL:   svcURL,
//						Users: []*auth.UserAuth{&userAuth},
//					},
//				}
//			} else {
//				server := config.GetOrCreateServer(svcURL)
//				server.Name = u.Host
//				server.Users = []*auth.UserAuth{&userAuth}
//			}
//			// lets save the file so that if we call LoadConfig() again we still have this defaulted user auth
//			err = authConfigSvc.SaveConfig()
//			if err != nil {
//				return authConfigSvc, err
//			}
//		}
//	}
//	return authConfigSvc, err
//}
//
//// SecretsLocation indicates the location where the secrets are stored
//func (f *factory) SecretsLocation() secrets.SecretsLocationKind {
//	client, namespace, err := f.CreateKubeClient()
//	if err != nil {
//		return secrets.FileSystemLocationKind
//	}
//	if f.secretLocation == nil {
//		devNs, _, err := kube.GetDevNamespace(client, namespace)
//		if err != nil {
//			devNs = kube.DefaultNamespace
//		}
//		f.secretLocation = secrets.NewSecretLocation(client, devNs)
//	}
//	return f.secretLocation.Location()
//}

// SetSecretsLocation configures the secrets location. It will persist the value in a config map
// if the persist flag is set.
func (f *factory) SetSecretsLocation(location secrets.SecretsLocationKind, persist bool) error {
	if f.secretLocation == nil {
		client, namespace, err := f.CreateKubeClient()
		if err != nil {
			return errors.Wrap(err, "creating the kube client")
		}
		f.secretLocation = secrets.NewSecretLocation(client, namespace)
	}
	err := f.secretLocation.SetLocation(location, persist)
	if err != nil {
		return errors.Wrapf(err, "setting the secrets location %q", location)
	}
	return nil
}

// ResetSecretsLocation resets the location of the secrets stored in memory
func (f *factory) ResetSecretsLocation() {
	f.secretLocation = nil
}


func (f *factory) CreateKubeClient() (kubernetes.Interface, string, error) {
	cfg, err := f.CreateKubeConfig()
	if err != nil {
		return nil, "", err
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, "", err
	}
	if client == nil {
		return nil, "", fmt.Errorf("Failed to create Kubernetes Client")
	}
	ns := ""
	config, _, err := f.kubeConfig.LoadConfig()
	if err != nil {
		return client, ns, err
	}
	ns = kube.CurrentNamespace(config)
	// TODO allow namsepace to be specified as a CLI argument!
	return client, ns, nil
}

func (f *factory) CreateGitProvider(gitURL string, message string, authConfigSvc auth.ConfigService, gitKind string, batchMode bool, gitter gits.Gitter, in terminal.FileReader, out terminal.FileWriter, errOut io.Writer) (gits.GitProvider, error) {
	gitInfo, err := gits.ParseGitURL(gitURL)
	if err != nil {
		return nil, err
	}
	return gitInfo.CreateProvider(f.IsInCluster(), authConfigSvc, gitKind, gitter, batchMode, in, out, errOut)
}

var kubeConfigCache *string

func createKubeConfig(offline bool) *string {
	if offline {
		panic("not supposed to be making a network connection")
	}
	var kubeconfig *string
	if kubeConfigCache != nil {
		return kubeConfigCache
	}
	if home := util.HomeDir(); home != "" {
		kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
	} else {
		kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
	}
	kubeConfigCache = kubeconfig
	return kubeconfig
}

func (f *factory) CreateKubeConfig() (*rest.Config, error) {
	masterURL := ""
	kubeConfigEnv := os.Getenv("KUBECONFIG")
	if kubeConfigEnv != "" {
		pathList := filepath.SplitList(kubeConfigEnv)
		return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			&clientcmd.ClientConfigLoadingRules{Precedence: pathList},
			&clientcmd.ConfigOverrides{ClusterInfo: clientcmdapi.Cluster{Server: masterURL}}).ClientConfig()
	}
	kubeconfig := createKubeConfig(f.offline)
	var config *rest.Config
	var err error
	if kubeconfig != nil {
		exists, err := util.FileExists(*kubeconfig)
		if err == nil && exists {
			// use the current context in kubeconfig
			config, err = clientcmd.BuildConfigFromFlags(masterURL, *kubeconfig)
			if err != nil {
				return nil, err
			}
		}
	}
	if config == nil {
		config, err = rest.InClusterConfig()
		if err != nil {
			return nil, err
		}
	}

	if config != nil && f.bearerToken != "" {
		config.BearerToken = f.bearerToken
		return config, nil
	}

	user := f.getImpersonateUser()
	if config != nil && user != "" && config.Impersonate.UserName == "" {
		config.Impersonate.UserName = user
	}

	// for testing purposes one can enable tracing of Kube REST API calls
	trace := os.Getenv("TRACE_KUBE_API")
	if trace == "1" || trace == "on" {
		config.WrapTransport = func(rt http.RoundTripper) http.RoundTripper {
			return &Tracer{rt}
		}
	}
	return config, nil
}

func (f *factory) getImpersonateUser() string {
	user := f.impersonateUser
	if user == "" {
		// this is really only used for testing really
		user = os.Getenv("JX_IMPERSONATE_USER")
	}
	return user
}

func (f *factory) CreateTable(out io.Writer) table.Table {
	return table.CreateTable(out)
}

// function to tell if we are running incluster
func (f *factory) IsInCluster() bool {
	_, err := rest.InClusterConfig()
	if err != nil {
		return false
	}
	return true
}


func (f *factory) CreateAuthConfigService(configName string, namespace string) (auth.ConfigService, error) {
	return auth.NewFileAuthConfigService(configName)
}

func (f *factory) AuthMergePipelineSecrets(config *auth.AuthConfig, secrets *corev1.SecretList, kind string, isCDPipeline bool) error {
	log.Logger().Debug("merging pipeline secrets with local secrets")
	if config == nil || secrets == nil {
		return nil
	}
	for _, secret := range secrets.Items {
		labels := secret.Labels
		annotations := secret.Annotations
		data := secret.Data
		if labels != nil && labels[kube.LabelKind] == kind && annotations != nil {
			u := annotations[kube.AnnotationURL]
			name := annotations[kube.AnnotationName]
			k := labels[kube.LabelServiceKind]
			if u != "" {
				server := config.GetOrCreateServer(u)
				if server != nil {
					// lets use the latest values from the credential
					if k != "" {
						server.Kind = k
					}
					if name != "" {
						server.Name = name
					}
					if data != nil {
						username := data[kube.SecretDataUsername]
						pwd := data[kube.SecretDataPassword]
						if len(username) > 0 && isCDPipeline {
							userAuth := config.FindUserAuth(u, string(username))
							if userAuth == nil {
								userAuth = &auth.UserAuth{
									Username: string(username),
									ApiToken: string(pwd),
								}
							} else if len(pwd) > 0 {
								userAuth.ApiToken = string(pwd)
							}
							config.SetUserAuth(u, userAuth)
							config.UpdatePipelineServer(server, userAuth)
						}
					}
				}
			}
		}
	}
	return nil
}


// CreateHelm creates a new Helm client
func (f *factory) CreateHelm(verbose bool,
	helmBinary string,
	noTiller bool,
	helmTemplate bool) helm.Helmer {

	if helmBinary == "" {
		helmBinary = "helm"
	}
	featureFlag := "none"
	if helmTemplate {
		featureFlag = "template-mode"
	} else if noTiller {
		featureFlag = "no-tiller-server"
	}
	if verbose {
		fmt.Sprintf("Using helmBinary %s with feature flag: %s", util.ColorInfo(helmBinary), util.ColorInfo(featureFlag))
	}
	helmCLI := helm.NewHelmCLI(helmBinary, helm.V2, "", verbose)
	var h helm.Helmer = helmCLI
	if helmTemplate {
		kubeClient, ns, _ := f.CreateKubeClient()
		h = helm.NewHelmTemplate(helmCLI, "", kubeClient, ns)
	} else {
		h = helmCLI
	}
	if noTiller && !helmTemplate {
		h.SetHost(helm.GetTillerAddress())
		helm.StartLocalTillerIfNotRunning()
	}
	return h
}