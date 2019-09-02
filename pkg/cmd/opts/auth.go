package opts

import (
	"fmt"
	"io/ioutil"

	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/jiubian-cicd/env-controller/pkg/auth"
	"github.com/jiubian-cicd/env-controller/pkg/gits"
	"github.com/jiubian-cicd/env-controller/pkg/kube"
)

// CreateGitAuthConfigServiceDryRun creates git auth config service, skips the effective creation when dry run is set
func (o *CommonOptions) CreateGitAuthConfigServiceDryRun(dryRun bool) (auth.ConfigService, error) {
	if dryRun {
		fileName := auth.GitAuthConfigFile
		return o.CreateGitAuthConfigServiceFromSecrets(fileName, nil)
	}
	return o.CreateGitAuthConfigService()
}


// CreateGitAuthConfigService creates git auth config service
func (o *CommonOptions) CreateGitAuthConfigService() (auth.ConfigService, error) {
	var secrets *corev1.SecretList
	var err error
	if !o.SkipAuthSecretsMerge {
		secrets, err = o.LoadPipelineSecrets(kube.ValueKindGit, "")
		if err != nil {
			kubeConfig, _, configLoadErr := o.Kube().LoadConfig()
			if configLoadErr != nil {
				fmt.Sprintf("WARNING: Could not load config: %s", configLoadErr)
			}

			ns := kube.CurrentNamespace(kubeConfig)
			if ns == "" {
				fmt.Sprintf("WARNING: Could not get the current namespace")
			}

			fmt.Sprintf("WARNING: The current user cannot query secrets in the namespace %s: %s", ns, err)
		}
	}

	fileName := auth.GitAuthConfigFile
	return o.CreateGitAuthConfigServiceFromSecrets(fileName, secrets)
}

// CreatePipelineUserGitAuthConfigService creates git auth config service for the pipeline user
func (o *CommonOptions) CreatePipelineUserGitAuthConfigService() (auth.ConfigService, error) {
	file, err := ioutil.TempFile("", "")
	if err != nil {
		return nil, err
	}
	fileName := file.Name()

	secrets, err := o.LoadPipelineSecrets(kube.ValueKindGit, "")
	if err != nil {
		kubeConfig, _, configLoadErr := o.Kube().LoadConfig()
		if configLoadErr != nil {
			fmt.Sprintf("WARNING: Could not load config: %s", configLoadErr)
		}

		ns := kube.CurrentNamespace(kubeConfig)
		if ns == "" {
			fmt.Sprintf("WARNING: Could not get the current namespace")
		}

		fmt.Sprintf("WARNING: The current user cannot query secrets in the namespace %s: %s", ns, err)
	}
	return o.CreateGitAuthConfigServiceFromSecrets(fileName, secrets)
}

// CreateGitAuthConfigServiceFromSecrets Creates a git auth config service from secrets
func (o *CommonOptions) CreateGitAuthConfigServiceFromSecrets(fileName string, secrets *corev1.SecretList) (auth.ConfigService, error) {
	_, namespace, err := o.KubeClientAndDevNamespace()
	if err != nil {
		// not returning an error here as we get this when attempting
		// to create a cluster when still connected to an old cluster
		fmt.Sprintf("failed to find development namespace - %s", err)
	}

	authConfigSvc, err := o.factory.CreateAuthConfigService(fileName, namespace)
	if err != nil {
		return authConfigSvc, err
	}

	config, err := authConfigSvc.LoadConfig()
	if err != nil {
		return authConfigSvc, err
	}

	if secrets != nil {
		err = o.factory.AuthMergePipelineSecrets(config, secrets, kube.ValueKindGit, false|| o.factory.IsInCluster())
		if err != nil {
			return authConfigSvc, err
		}
	}

	// lets add a default if there's none defined yet
	if len(config.Servers) == 0 {
		// if in cluster then there's no user configfile, so check for env vars first
		userAuth := auth.CreateAuthUserFromEnvironment("GIT")

		if !userAuth.IsInvalid() {
			// if no config file is being used lets grab the git server from the current directory
			server, err := o.Git().Server("")
			if err != nil {
				fmt.Sprintf("WARNING: unable to get remote Git repo server, %v", err)
				server = "https://github.com"
			}
			config.Servers = []*auth.AuthServer{
				{
					Name:  "Git",
					URL:   server,
					Users: []*auth.UserAuth{&userAuth},
				},
			}
		}
	}

	if len(config.Servers) == 0 {
		config.Servers = []*auth.AuthServer{
			{
				Name:  "GitHub",
				URL:   "https://github.com",
				Kind:  gits.KindGitHub,
				Users: []*auth.UserAuth{},
			},
		}
	}

	return authConfigSvc, nil
}

//// CreateChatAuthConfigService creates a new chat auth service
//func (o *CommonOptions) CreateChatAuthConfigService() (auth.ConfigService, error) {
//	secrets, err := o.LoadPipelineSecrets(kube.ValueKindChat, "")
//	if err != nil {
//		fmt.Sprintf("The current user cannot query pipeline chat secrets: %s", err)
//	}
//	_, namespace, err := o.KubeClientAndDevNamespace()
//	if err != nil {
//		return nil, errors.Wrapf(err, "failed to find development namespace")
//	}
//	return o.factory.CreateChatAuthConfigService(namespace, secrets)
//}
//
//// LoadPipelineSecrets loads the pipeline secrets from kubernetes secrets
func (o *CommonOptions) LoadPipelineSecrets(kind, serviceKind string) (*corev1.SecretList, error) {
	// TODO return empty list if not inside a pipeline?
	kubeClient, curNs, err := o.KubeClientAndNamespace()
	if err != nil {
		return nil, fmt.Errorf("Failed to create a Kubernetes client %s", err)
	}
	ns := curNs
	if !o.RemoteCluster {
		ns = curNs
		if err != nil {
			return nil, fmt.Errorf("Failed to get the development environment %s", err)
		}
	}
	var selector string
	if kind != "" {
		selector = kube.LabelKind + "=" + kind
	}
	if serviceKind != "" {
		selector = kube.LabelServiceKind + "=" + serviceKind
	}

	opts := metav1.ListOptions{
		LabelSelector: selector,
	}
	return kubeClient.CoreV1().Secrets(ns).List(opts)
}

// PickPipelineUserAuth returns the user auth for pipeline user
func (o *CommonOptions) PickPipelineUserAuth(config *auth.AuthConfig, server *auth.AuthServer) (*auth.UserAuth, error) {
	userName := config.PipeLineUsername
	if userName != "" {
		userAuth := config.GetOrCreateUserAuth(server.URL, userName)
		if userAuth != nil {
			return userAuth, nil
		}
	}
	var userAuth *auth.UserAuth
	var err error
	url := server.URL
	userAuths := config.FindUserAuths(url)
	if len(userAuths) > 1 {
		userAuth, err = config.PickServerUserAuth(server, "user name for the Pipeline", o.BatchMode, "", o.In, o.Out, o.Err)
		if err != nil {
			return userAuth, err
		}
	}
	if userAuth != nil {
		config.PipeLineUsername = userAuth.Username
	} else {
		// lets create an empty one for now
		userAuth = &auth.UserAuth{}
	}
	return userAuth, nil
}
//
//// GetDefaultAdminPassword returns the default admin password from dev namespace
//func (o *CommonOptions) GetDefaultAdminPassword(devNamespace string) (string, error) {
//	client, err := o.KubeClient() // cache may not have been created yet...
//	if err != nil {
//		return "", fmt.Errorf("cannot obtain k8s client %v", err)
//	}
//	basicAuth, err := client.CoreV1().Secrets(devNamespace).Get(JXInstallConfig, v1.GetOptions{})
//	if err != nil {
//		return "", fmt.Errorf("cannot find secret %s in namespace %s: %v", kube.SecretBasicAuth, devNamespace, err)
//	}
//	adminSecrets := basicAuth.Data[AdminSecretsFile]
//	adminConfig := config.AdminSecretsConfig{}
//
//	err = yaml.Unmarshal(adminSecrets, &adminConfig)
//	if err != nil {
//		return "", err
//	}
//	return adminConfig.Jenkins.JenkinsSecret.Password, nil
//}
//
//// AddonAuthConfigService creates the addon auth config service
//func (o *CommonOptions) AddonAuthConfigService(secrets *corev1.SecretList) (auth.ConfigService, error) {
//	if o.factory == nil {
//		return nil, errors.New("command factory is not initialized")
//	}
//	_, namespace, err := o.KubeClientAndDevNamespace()
//	if err != nil {
//		return nil, errors.Wrapf(err, "failed to find development namespace")
//	}
//	return o.factory.CreateAddonAuthConfigService(namespace, secrets)
//}
//
//// JenkinsAuthConfigService creates the jenkins auth config service
//func (o *CommonOptions) JenkinsAuthConfigService(client kubernetes.Interface, namespace string, selector *JenkinsSelectorOptions) (auth.ConfigService, error) {
//	if o.factory == nil {
//		return nil, errors.New("command factory is not initialized")
//	}
//	prow, err := o.IsProw()
//	if err != nil {
//		return nil, err
//	}
//	if prow {
//		selector.UseCustomJenkins = true
//	}
//	jenkinsServiceName := ""
//	kubeClient, ns, err := o.KubeClientAndDevNamespace()
//	if err != nil {
//		return nil, err
//	}
//	if namespace == "" {
//		namespace = ns
//	}
//	if selector.IsCustom() {
//		jenkinsServiceName, err = o.PickCustomJenkinsName(selector, kubeClient, ns)
//		if err != nil {
//			return nil, err
//		}
//	}
//	return o.factory.CreateJenkinsAuthConfigService(client, namespace, jenkinsServiceName)
//}
//
//// ChartmuseumAuthConfigService creates the chart museum auth config service
//func (o *CommonOptions) ChartmuseumAuthConfigService() (auth.ConfigService, error) {
//	if o.factory == nil {
//		return nil, errors.New("command factory is not initialized")
//	}
//	_, namespace, err := o.KubeClientAndDevNamespace()
//	if err != nil {
//		return nil, errors.Wrapf(err, "failed to find development namespace")
//	}
//	return o.factory.CreateChartmuseumAuthConfigService(namespace)
//}

// AuthConfigService creates the auth config service for given file
func (o *CommonOptions) AuthConfigService(file string) (auth.ConfigService, error) {
	if o.factory == nil {
		return nil, errors.New("command factory is not initialized")
	}
	_, namespace, err := o.KubeClientAndDevNamespace()
	if err != nil {
		return nil, errors.Wrapf(err, "failed to find development namespace")
	}
	return o.factory.CreateAuthConfigService(file, namespace)
}
