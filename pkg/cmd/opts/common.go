package opts

import (
	"fmt"
	"github.com/jiubian-cicd/env-controller/pkg/helm"
	"github.com/jiubian-cicd/env-controller/pkg/secreturl"
	"github.com/spf13/viper"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/pflag"

	"github.com/pkg/errors"

	"github.com/jiubian-cicd/env-controller/pkg/auth"
	"github.com/jiubian-cicd/env-controller/pkg/cmd/clients"
	"github.com/jiubian-cicd/env-controller/pkg/gits"
	"github.com/jiubian-cicd/env-controller/pkg/util"
	"github.com/spf13/cobra"
	"gopkg.in/AlecAivazis/survey.v1"
	"gopkg.in/AlecAivazis/survey.v1/terminal"
	gitcfg "gopkg.in/src-d/go-git.v4/config"
	"k8s.io/client-go/kubernetes"

	"github.com/jiubian-cicd/env-controller/pkg/kube"
)

// LogLevel represents the logging level when reporting feedback
type LogLevel string

const (
	OptionAlias            = "alias"
	OptionApplication      = "app"
	OptionBatchMode        = "batch-mode"
	OptionClusterName      = "cluster-name"
	OptionEnvironment      = "env"
	OptionInstallDeps      = "install-dependencies"
	OptionLabel            = "label"
	OptionName             = "name"
	OptionNamespace        = "namespace"
	OptionNoBrew           = "no-brew"
	OptionRelease          = "release"
	OptionServerName       = "name"
	OptionOutputDir        = "output-dir"
	OptionServerURL        = "url"
	OptionSkipAuthSecMerge = "skip-auth-secrets-merge"
	OptionTimeout          = "timeout"
	OptionVerbose          = "verbose"

	BranchPatternCommandName      = "branchpattern"
	QuickStartLocationCommandName = "quickstartlocation"

	// LogInfo info level logging
	LogInfo LogLevel = "INFO"
	// LogWarning warning level logging
	LogWarning LogLevel = "WARN"
	// LogError error level logging
	LogError LogLevel = "ERROR"
)

var (
	BranchPatternCommandAliases = []string{
		"branch pattern",
	}

	QuickStartLocationCommandAliases = []string{
		QuickStartLocationCommandName + "s", "quickstartloc", "qsloc",
	}
)

// CommonOptions contains common options and helper methods
type CommonOptions struct {

	HMACToken   string
	Args                   []string
	BatchMode              bool
	Cmd                    *cobra.Command
	Domain                 string
	Err                    io.Writer
	ExternalJenkinsBaseURL string
	In                     terminal.FileReader
	InstallDependencies    bool
	NoBrew                 bool
	RemoteCluster          bool
	Out                    terminal.FileWriter
	ServiceAccount         string
	SkipAuthSecretsMerge   bool
	Username               string
	Verbose                bool
	NotifyCallback         func(LogLevel, string)
	kuber                  kube.Kuber
	git                    gits.Gitter
	helm                   helm.Helmer
	factory                clients.Factory
	kubeClient             kubernetes.Interface
	secretURLClient        secreturl.Client
	currentNamespace       string
	devNamespace           string
	environmentsDir        string
	NameServers            []string
	AdvancedMode           bool
	ConfigFile             string
}

type ServerFlags struct {
	ServerName string
	ServerURL  string
}

// IsEmpty returns true if the server flags and server URL are tempry
func (f *ServerFlags) IsEmpty() bool {
	return f.ServerName == "" && f.ServerURL == ""
}


// NotifyProgress by default logs info to the console but a custom callback can be added to send feedback to, say, a web UI
func (o *CommonOptions) NotifyProgress(level LogLevel, format string, args ...interface{}) {
	if o.NotifyCallback != nil {
		text := fmt.Sprintf(format, args...)
		o.NotifyCallback(level, text)
		return
	}
	switch level {
	case LogInfo:
		fmt.Sprintf(format, args...)
	case LogWarning:
		fmt.Sprintf(format, args...)
	default:
		fmt.Sprintf(format, args...)
	}
}


// AddBaseFlags adds the base flags for all commands
func (o *CommonOptions) AddBaseFlags(cmd *cobra.Command) {
	defaultBatchMode := false
	if os.Getenv("JX_BATCH_MODE") == "true" {
		defaultBatchMode = true
	}
	cmd.PersistentFlags().BoolVarP(&o.BatchMode, OptionBatchMode, "b", defaultBatchMode, "Runs in batch mode without prompting for user input")
	cmd.PersistentFlags().BoolVarP(&o.Verbose, OptionVerbose, "", false, "Enables verbose output")

	o.Cmd = cmd
}

// NewCommonOptionsWithTerm creates a new CommonOptions instance with given terminal input, output and error
func NewCommonOptionsWithTerm(factory clients.Factory, in terminal.FileReader, out terminal.FileWriter, err io.Writer) *CommonOptions {
	return &CommonOptions{
		factory: factory,
		In:      in,
		Out:     out,
		Err:     err,
	}
}

// GetConfiguration read the config file marshal into a config struct
func (o *CommonOptions) GetConfiguration(config interface{}) error {
	configFile := o.ConfigFile
	if configFile != "" {
		viper.SetConfigFile(configFile)
		viper.SetConfigType("yaml")
		if err := viper.ReadInConfig(); err != nil {
			if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
				fmt.Sprintf("Config file %s not found", configFile)
			} else {
				return err
			}
		} else {
			err = viper.Unmarshal(config)
			if err != nil {
				return errors.Wrap(err, "unable to decode into config struct")
			}
		}
	}
	createDebugConfigFile("debug", "config.yaml")
	return nil
}

func createDebugConfigFile(dir string, file string) {
	wkDir, err := util.ConfigDir()
	if err != nil {
		fmt.Sprintf("error determining config dir %v", err)
	} else {
		dir := filepath.Join(wkDir, dir)
		if err = os.MkdirAll(dir, util.DefaultWritePermissions); err != nil {
			fmt.Sprintf("Error making directory: %s %s", dir, err)
		}
		configFile := filepath.Join(dir, file)
		if err = viper.WriteConfigAs(configFile); err != nil {
			fmt.Sprintf("Error writing config file %s", err)
		}
	}
}


// KubeClient returns or creates the kube client
func (o *CommonOptions) KubeClient() (kubernetes.Interface, error) {
	if o.kubeClient == nil {
		kubeClient, currentNs, err := o.factory.CreateKubeClient()
		if err != nil {
			return nil, err
		}
		o.kubeClient = kubeClient
		if o.currentNamespace == "" {
			o.currentNamespace = currentNs
		}
	}
	if o.kubeClient == nil {
		return o.kubeClient, fmt.Errorf("failed to create KubeClient")
	}
	return o.kubeClient, nil
}

// KubeClientAndNamespace returns or creates the kube client and the current namespace
func (o *CommonOptions) KubeClientAndNamespace() (kubernetes.Interface, string, error) {
	client, err := o.KubeClient()
	return client, o.currentNamespace, err
}

// SetKubeClient sets the kube client
func (o *CommonOptions) SetKubeClient(kubeClient kubernetes.Interface) {
	o.kubeClient = kubeClient
}

// KubeClientAndDevNamespace returns a kube client and the development namespace
func (o *CommonOptions) KubeClientAndDevNamespace() (kubernetes.Interface, string, error) {
	kubeClient, curNs, err := o.KubeClientAndNamespace()
	if err != nil {
		return nil, "", err
	}
	if o.devNamespace == "" {
		o.devNamespace = curNs
	}
	return kubeClient, o.devNamespace, err
}

//GetDeployNamespace returns the namespace option from the command line option if defined otherwise we try
//the $DEPLOY_NAMESPACE environment variable. If none of those are found lets use the current
//kubernetes namespace value
func (o *CommonOptions) GetDeployNamespace(namespaceOption string) (string, error) {
	ns := namespaceOption
	if ns == "" {
		ns = os.Getenv("DEPLOY_NAMESPACE")
	}

	if ns == "" {
		var err error
		_, ns, err = o.KubeClientAndNamespace()
		if err != nil {
			return ns, err
		}
		fmt.Println("No --namespace option specified or $DEPLOY_NAMESPACE environment variable available so defaulting to using namespace %s", ns)
	}
	return ns, nil
}



// Git returns the git client
func (o *CommonOptions) Git() gits.Gitter {
	if o.git == nil {
		o.git = gits.NewGitCLI()
	}
	return o.git
}

// SetGit sets the git client
func (o *CommonOptions) SetGit(git gits.Gitter) {
	o.git = git
}

//// SetFakeGitProvider set the fake git provider for testing purposes
//func (o *CommonOptions) SetFakeGitProvider(provider *gits.FakeProvider) {
//	o.fakeGitProvider = provider
//}
//
// NewHelm cerates a new helm client from the given list of parameters
func (o *CommonOptions) NewHelm(verbose bool, helmBinary string, noTiller bool, helmTemplate bool) helm.Helmer {
	o.helm = o.factory.CreateHelm(o.Verbose, helmBinary, noTiller, helmTemplate)
	return o.helm
}

//// Helm returns or creates the helm client
func (o *CommonOptions) Helm() helm.Helmer {
	if o.helm == nil {
		helmBinary := "helm"
		return o.NewHelm(o.Verbose, helmBinary, false, false)
	}
	return o.helm
}

// SetHelm sets the helmer used for this object
func (o *CommonOptions) SetHelm(helmer helm.Helmer) {
	o.helm = helmer
}

//Kube returns the k8s config client
func (o *CommonOptions) Kube() kube.Kuber {
	if o.kuber == nil {
		o.kuber = kube.NewKubeConfig()
	}
	return o.kuber
}

// SetKube  sets the kube config client
func (o *CommonOptions) SetKube(kuber kube.Kuber) {
	o.kuber = kuber
}

//
//// TeamAndEnvironmentNames returns team and environment namespace
//func (o *CommonOptions) TeamAndEnvironmentNames() (string, string, error) {
//	kubeClient, currentNs, err := o.KubeClientAndNamespace()
//	if err != nil {
//		return "", "", err
//	}
//	return kube.GetDevNamespace(kubeClient, currentNs)
//}

// AddGitServerFlags add git server flags to the given cobra command
func (o *ServerFlags) AddGitServerFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&o.ServerName, OptionServerName, "n", "", "The name of the Git server to add a user")
	cmd.Flags().StringVarP(&o.ServerURL, OptionServerURL, "u", "", "The URL of the Git server to add a user")
}

// FindGitServer finds the Git server from the given flags or returns an error
func (o *CommonOptions) FindGitServer(config *auth.AuthConfig, serverFlags *ServerFlags) (*auth.AuthServer, error) {
	return o.FindServer(config, serverFlags, "git", "Try creating one via: jx create git server", false)
}

// FindIssueTrackerServer finds the issue tracker server from the given flags or returns an error
func (o *CommonOptions) FindIssueTrackerServer(config *auth.AuthConfig, serverFlags *ServerFlags) (*auth.AuthServer, error) {
	return o.FindServer(config, serverFlags, "issues", "Try creating one via: jx create tracker server", false)
}

// FindChatServer finds the chat server from the given flags or returns an error
func (o *CommonOptions) FindChatServer(config *auth.AuthConfig, serverFlags *ServerFlags) (*auth.AuthServer, error) {
	return o.FindServer(config, serverFlags, "chat", "Try creating one via: jx create chat server", false)
}

// FindAddonServer finds the addon server from the given flags or returns an error
func (o *CommonOptions) FindAddonServer(config *auth.AuthConfig, serverFlags *ServerFlags, kind string) (*auth.AuthServer, error) {
	return o.FindServer(config, serverFlags, kind, "Try creating one via: jx create addon", true)
}

// FindServer find the server flags from the given flags or returns an error
func (o *CommonOptions) FindServer(config *auth.AuthConfig, serverFlags *ServerFlags, defaultKind string, missingServerDescription string, lazyCreate bool) (*auth.AuthServer, error) {
	kind := defaultKind
	var server *auth.AuthServer
	if serverFlags.ServerURL != "" {
		server = config.GetServer(serverFlags.ServerURL)
		if server == nil {
			if lazyCreate {
				return config.GetOrCreateServerName(serverFlags.ServerURL, serverFlags.ServerName, kind), nil
			}
			return nil, util.InvalidOption(OptionServerURL, serverFlags.ServerURL, config.GetServerURLs())
		}
	}
	if server == nil && serverFlags.ServerName != "" {
		name := serverFlags.ServerName
		if lazyCreate {
			server = config.GetOrCreateServerName(serverFlags.ServerURL, name, kind)
		} else {
			server = config.GetServerByName(name)
		}
		if server == nil {
			return nil, util.InvalidOption(OptionServerName, name, config.GetServerNames())
		}
	}
	if server == nil {
		name := config.CurrentServer
		if name != "" && o.BatchMode {
			server = config.GetServerByName(name)
			if server == nil {
				fmt.Sprintf("Current server %s no longer exists", name)
			}
		}
	}
	if server == nil && len(config.Servers) == 1 {
		server = config.Servers[0]
	}
	if server == nil && len(config.Servers) > 1 {
		if o.BatchMode {
			return nil, fmt.Errorf("Multiple servers found. Please specify one via the %s option", OptionServerName)
		}
		defaultServerName := ""
		if config.CurrentServer != "" {
			s := config.GetServer(config.CurrentServer)
			if s != nil {
				defaultServerName = s.Name
			}
		}
		name, err := util.PickNameWithDefault(config.GetServerNames(), "Pick server to use: ", defaultServerName, "", o.In, o.Out, o.Err)
		if err != nil {
			return nil, err
		}
		server = config.GetServerByName(name)
		if server == nil {
			return nil, fmt.Errorf("Could not find the server for name %s", name)
		}
	}
	if server == nil {
		return nil, fmt.Errorf("Could not find a %s. %s", kind, missingServerDescription)
	}
	return server, nil
}
//
//// FindService finds the given service and returns its URL
//func (o *CommonOptions) FindService(name string) (string, error) {
//	client, ns, err := o.KubeClientAndNamespace()
//	if err != nil {
//		return "", err
//	}
//	devNs, _, err := kube.GetDevNamespace(client, ns)
//	if err != nil {
//		return "", err
//	}
//	url, err := services.FindServiceURL(client, ns, name)
//	if url == "" {
//		url, err = services.FindServiceURL(client, devNs, name)
//	}
//	if url == "" {
//		names, err := services.GetServiceNames(client, ns, name)
//		if err != nil {
//			return "", err
//		}
//		if len(names) > 1 {
//			name, err = util.PickName(names, "Pick service to open: ", "", o.In, o.Out, o.Err)
//			if err != nil {
//				return "", err
//			}
//			if name != "" {
//				url, err = services.FindServiceURL(client, ns, name)
//			}
//		} else if len(names) == 1 {
//			// must have been a filter
//			url, err = services.FindServiceURL(client, ns, names[0])
//		}
//		if url == "" {
//			return "", fmt.Errorf("Could not find URL for service %s in namespace %s", name, ns)
//		}
//	}
//	return url, nil
//}
//
//
//// FindServiceInNamespace searches a service in a given namespace. If found, it returns the service URL
//func (o *CommonOptions) FindServiceInNamespace(name string, ns string) (string, error) {
//	client, curNs, err := o.KubeClientAndNamespace()
//	if err != nil {
//		return "", err
//	}
//	if ns == "" {
//		ns = curNs
//	}
//	url, err := services.FindServiceURL(client, ns, name)
//	if url == "" {
//		names, err := services.GetServiceNames(client, ns, name)
//		if err != nil {
//			return "", err
//		}
//		if len(names) > 1 {
//			name, err = util.PickName(names, "Pick service to open: ", "", o.In, o.Out, o.Err)
//			if err != nil {
//				return "", err
//			}
//			if name != "" {
//				url, err = services.FindServiceURL(client, ns, name)
//			}
//		} else if len(names) == 1 {
//			// must have been a filter
//			url, err = services.FindServiceURL(client, ns, names[0])
//		}
//		if url == "" {
//			return "", fmt.Errorf("Could not find URL for service %s in namespace %s", name, ns)
//		}
//	}
//	return url, nil
//}

// Retry executes a given function and reties 'attempts' times with a delay of 'sleep' between the executions
func (o *CommonOptions) Retry(attempts int, sleep time.Duration, call func() error) (err error) {
	for i := 0; ; i++ {
		err = call()
		if err == nil {
			return
		}

		if i >= (attempts - 1) {
			break
		}

		time.Sleep(sleep)

		fmt.Sprintf("\nretrying after error:%s\n", err)
	}
	return fmt.Errorf("after %d attempts, last error: %s", attempts, err)
}

// FatalError is a wrapper structure around regular error indicating that re(try) processing flow should be interrupted
// immediately.
type FatalError struct {
	E error
}

// Error converts a fatal error into a string
func (err *FatalError) Error() string {
	return fmt.Sprintf("fatal error: %s", err.E.Error())
}

// RetryUntilFatalError executes a given function call with retry when the function fails. It stops retrying when a fatal
// error is encountered.
func (o *CommonOptions) RetryUntilFatalError(attempts int, sleep time.Duration, call func() (*FatalError, error)) (err error) {
	for i := 0; ; i++ {
		fatalErr, err := call()
		if fatalErr != nil {
			return fatalErr.E
		}
		if err == nil {
			return nil
		}

		if i >= (attempts - 1) {
			break
		}

		time.Sleep(sleep)

		fmt.Sprintf("retrying after error:%s", err)
	}
	return fmt.Errorf("after %d attempts, last error: %s", attempts, err)
}

// RetryQuiet executes a given function call with retry when an error occurs without printing any logs
func (o *CommonOptions) RetryQuiet(attempts int, sleep time.Duration, call func() error) (err error) {
	lastMessage := ""
	dot := false

	for i := 0; ; i++ {
		err = call()
		if err == nil {
			if dot {
				fmt.Println()
			}
			return
		}

		if i >= (attempts - 1) {
			break
		}

		time.Sleep(sleep)

		message := fmt.Sprintf("retrying after error: %s", err)
		if lastMessage == message {
			fmt.Sprintf(".")
			dot = true
		} else {
			lastMessage = message
			if dot {
				dot = false
				fmt.Println()
			}
			fmt.Sprintf("%s\n", lastMessage)
		}
	}
	return fmt.Errorf("after %d attempts, last error: %s", attempts, err)
}

// RetryQuietlyUntilTimeout executes a function call with retry when an error occurs. It stops retrying when the timeout is reached.
func (o *CommonOptions) RetryQuietlyUntilTimeout(timeout time.Duration, sleep time.Duration, call func() error) (err error) {
	timeoutTime := time.Now().Add(timeout)

	lastMessage := ""
	dot := false

	for i := 0; ; i++ {
		err = call()
		if err == nil {
			if dot {
				fmt.Println()
			}
			return
		}

		if time.Now().After(timeoutTime) {
			return fmt.Errorf("Timed out after %s, last error: %s", timeout.String(), err)
		}

		time.Sleep(sleep)

		message := fmt.Sprintf("retrying after error: %s", err)
		if lastMessage == message {
			fmt.Sprintf(".")
			dot = true
		} else {
			lastMessage = message
			if dot {
				dot = false
				fmt.Println()
			}
			fmt.Sprintf("%s\n", lastMessage)
		}
	}
}

// RetryUntilTrueOrTimeout waits until complete is true, an error occurs or the timeout
func (o *CommonOptions) RetryUntilTrueOrTimeout(timeout time.Duration, sleep time.Duration, call func() (bool, error)) (err error) {
	timeoutTime := time.Now().Add(timeout)

	for i := 0; ; i++ {
		complete, err := call()
		if complete || err != nil {
			return err
		}
		if time.Now().After(timeoutTime) {
			return fmt.Errorf("Timed out after %s, last error: %s", timeout.String(), err)
		}

		time.Sleep(sleep)
	}
}

// PickGitRemoteURL picks a git remote URL from git config, or prompts to the user if no URL is found
func (o *CommonOptions) PickGitRemoteURL(config *gitcfg.Config) (string, error) {
	surveyOpts := survey.WithStdio(o.In, o.Out, o.Err)
	urls := []string{}
	if config.Remotes != nil {
		for _, r := range config.Remotes {
			if r.URLs != nil {
				for _, u := range r.URLs {
					urls = append(urls, u)
				}
			}
		}
	}
	if len(urls) == 1 {
		return urls[0], nil
	}
	url := ""
	if len(urls) > 1 {
		prompt := &survey.Select{
			Message: "Choose a remote git URL:",
			Options: urls,
		}
		err := survey.AskOne(prompt, &url, nil, surveyOpts)
		if err != nil {
			return "", err
		}
	}
	return url, nil
}


// GetIn returns the command inputs writer
func (o *CommonOptions) GetIn() terminal.FileReader {
	return o.In
}

// GetOut returns the command output writer
func (o *CommonOptions) GetOut() terminal.FileWriter {
	return o.Out
}

// GetErr returns the command error writer
func (o *CommonOptions) GetErr() io.Writer {
	return o.Err
}

// EnvironmentsDir is the local directory the environments are stored in  - can be faked out for tests
func (o *CommonOptions) EnvironmentsDir() (string, error) {
	if o.environmentsDir == "" {
		var err error
		o.environmentsDir, err = util.EnvironmentsDir()
		if err != nil {
			return "", err
		}
	}
	return o.environmentsDir, nil
}

// SetEnvironmentsDir sets the environment directory
func (o *CommonOptions) SetEnvironmentsDir(dir string) {
	o.environmentsDir = dir
}

// SeeAlsoText returns text to describe which other commands to look at which are related to the current command
func SeeAlsoText(commands ...string) string {
	if len(commands) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("\nSee Also:\n\n")

	for _, command := range commands {
		u := "https://jenkins-x.io/commands/" + strings.Replace(command, " ", "_", -1)
		sb.WriteString(fmt.Sprintf("* %s : [%s](%s)\n", command, u, u))
	}
	sb.WriteString("\n")
	return sb.String()
}



// IsFlagExplicitlySet checks whether the flag with the specified name is explicitly set by the user.
// If so, true is returned, false otherwise.
func (o *CommonOptions) IsFlagExplicitlySet(flagName string) bool {
	explicit := false
	explicitlySetFunc := func(f *pflag.Flag) {
		if f.Name == flagName {
			explicit = true
		}
	}
	o.Cmd.Flags().Visit(explicitlySetFunc)
	return explicit
}

// IsConfigExplicitlySet checks whether the flag or config with the specified name is explicitly set by the user.
// If so, true is returned, false otherwise.
func (o *CommonOptions) IsConfigExplicitlySet(configPath, configKey string) bool {
	if o.IsFlagExplicitlySet(configKey) || o.configExists(configPath, configKey) {
		return true
	}
	return false
}

func (o *CommonOptions) configExists(configPath, configKey string) bool {
	if configPath != "" {
		path := append(strings.Split(configPath, "."), configKey)
		configMap := viper.GetStringMap(path[0])
		m := map[string]interface{}{path[0]: configMap}

		for _, k := range path {
			m2, ok := m[k]
			if !ok {
				return false
			}
			m3, ok := m2.(map[string]interface{})
			if !ok {
				if k != configKey {
					return false
				}
			}
			m = m3
		}
		return true
	}
	return viper.InConfig(configKey)
}
