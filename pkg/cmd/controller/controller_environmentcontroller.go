package controller

import (
	"encoding/json"
	"fmt"
	"github.com/jiubian-cicd/env-controller/pkg/log"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jiubian-cicd/env-controller/pkg/cmd/helper"
	"github.com/jiubian-cicd/env-controller/pkg/cmd/opts"
	"github.com/jiubian-cicd/env-controller/pkg/cmd/templates"
	"github.com/jiubian-cicd/env-controller/pkg/gits"
	"github.com/jiubian-cicd/env-controller/pkg/kube/services"
	"github.com/jiubian-cicd/env-controller/pkg/util"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	environmentControllerService       = "env-controller"
	environmentControllerHmacSecret    = "env-controller-hmac"
	environmentControllerHmacSecretKey = "hmac"
	helloMessage                       = "hello from the Env-Controller\n"
)

// ControllerEnvironmentOptions holds the command line arguments
type ControllerEnvironmentOptions struct {
	*opts.CommonOptions
	BindAddress           string
	Path                  string
	Port                  int
	NoGitCredeentialsInit bool
	NoRegisterWebHook     bool
	RequireHeaders        bool
	GitServerURL          string
	GitOwner              string
	GitRepo               string
	GitKind               string
	SourceURL             string
	WebHookURL            string
	Branch                string
	PushRef               string
	Dir                   string
	Labels                map[string]string
	GitRepositoryOptions   gits.GitRepositoryOptions

	secret                []byte
}

var (
	controllerEnvironmentsLong = templates.LongDesc(`A controller which takes a webhook and updates the environment via GitOps for remote clusters`)

	controllerEnvironmentsExample = templates.Examples(`
			# run the environment controller
			jx controller environment
		`)
)

// NewCmdControllerEnvironment creates the command
func NewCmdControllerEnvironment(commonOpts *opts.CommonOptions) *cobra.Command {
	options := ControllerEnvironmentOptions{
		CommonOptions: commonOpts,
	}
	cmd := &cobra.Command{
		Use:     "environment",
		Short:   "A controller which takes a webhook and updates the environment via GitOps",
		Long:    controllerEnvironmentsLong,
		Example: controllerEnvironmentsExample,
		Run: func(cmd *cobra.Command, args []string) {
			options.Cmd = cmd
			options.Args = args
			err := options.Run()
			helper.CheckErr(err)
		},
	}

	cmd.Flags().IntVarP(&options.Port, "port", "", 8080, "The TCP port to listen on.")
	cmd.Flags().StringVarP(&options.BindAddress, "bind", "", "",
		"The interface address to bind to (by default, will listen on all interfaces/addresses).")
	cmd.Flags().StringVarP(&options.Path, "path", "", "/hook",
		"The path to listen on for requests to trigger a pipeline run.")
	cmd.Flags().BoolVarP(&options.NoGitCredeentialsInit, "no-git-init", "", false, "Disables checking we have setup git credentials on startup")
	cmd.Flags().BoolVarP(&options.RequireHeaders, "require-headers", "", true, "If enabled we reject webhooks which do not have the github headers: 'X-GitHub-Event' and 'X-GitHub-Delivery'")
	cmd.Flags().BoolVarP(&options.NoRegisterWebHook, "no-register-webhook", "", false, "Disables checking to register the webhook on startup")
	cmd.Flags().StringVarP(&options.SourceURL, "source-url", "s", "", "The source URL of the environment git repository")
	cmd.Flags().StringVarP(&options.GitServerURL, "git-server-url", "", "", "The git server URL. If not specified defaults to $GIT_SERVER_URL")
	cmd.Flags().StringVarP(&options.GitKind, "git-kind", "", "", "The kind of git repository. Should be one of: "+strings.Join(gits.KindGits, ", ")+". If not specified defaults to $GIT_KIND")
	cmd.Flags().StringVarP(&options.GitOwner, "owner", "o", "", "The git repository owner. If not specified defaults to $OWNER")
	cmd.Flags().StringVarP(&options.GitRepo, "repo", "", "", "The git repository name. If not specified defaults to $REPO")
	cmd.Flags().StringVarP(&options.WebHookURL, "webhook-url", "w", "", "The external WebHook URL of this controller to register with the git provider. If not specified defaults to $WEBHOOK_URL")
	cmd.Flags().StringVarP(&options.PushRef, "push-ref", "", "refs/heads/master", "The git ref passed from the WebHook which should trigger a new deploy pipeline to trigger. Defaults to only webhooks from the master branch")
	cmd.Flags().StringVarP(&options.Dir, "dir", "", "", "The directory in which the git repo is checked out, by default the working directory")

	opts.AddGitRepoOptionsArguments(cmd, &options.GitRepositoryOptions)
	return cmd
}

// Run will implement this command
func (o *ControllerEnvironmentOptions) Run() error {

	if o.Path == "" {
		return util.MissingOption("path")
	}

	var err error
	if o.SourceURL != "" {
		gitInfo, err := gits.ParseGitURL(o.SourceURL)
		if err != nil {
			return err
		}
		if o.GitServerURL == "" {
			o.GitServerURL = gitInfo.ProviderURL()
		}
		if o.GitOwner == "" {
			o.GitOwner = gitInfo.Organisation
		}
		if o.GitRepo == "" {
			o.GitRepo = gitInfo.Name
		}
	}
	if o.GitServerURL == "" {
		o.GitServerURL = os.Getenv("GIT_SERVER_URL")
		if o.GitServerURL == "" {
			return util.MissingOption("git-server-url")
		}
	}

	o.BatchMode = os.Getenv("BATCH_MODE") == "true"

	if o.GitKind == "" {
		o.GitKind = os.Getenv("GIT_KIND")
		if o.GitKind == "" {
			fmt.Sprintf("No $GIT_KIND defined or --git-kind supplied to assuming GitHub.com environment git repository")
		}
	}
	if o.GitOwner == "" {
		o.GitOwner = os.Getenv("OWNER")
		if o.GitOwner == "" {
			return util.MissingOption("owner")
		}
	}
	if o.GitRepo == "" {
		o.GitRepo = os.Getenv("REPO")
		if o.GitRepo == "" {
			return util.MissingOption("repo")
		}
	}

	if o.Branch == "" {
		o.Branch = os.Getenv("BRANCH")
		if o.Branch == "" {
			o.Branch = "master"
		}
	}
	if o.WebHookURL == "" {
		o.WebHookURL = os.Getenv("WEBHOOK_URL")
		if o.WebHookURL == "" {
			o.WebHookURL, err = o.discoverWebHookURL()
			if err != nil {
				return err
			}
		}
	}
	if o.SourceURL == "" {
		o.SourceURL = util.UrlJoin(o.GitServerURL, o.GitOwner, o.GitRepo)
	}
	log.Logger().Infof("using environment source directory %s and external webhook URL: %s", util.ColorInfo(o.SourceURL), util.ColorInfo(o.WebHookURL))
	o.secret, err = o.loadOrCreateHmacSecret()
	if err != nil {
		return errors.Wrapf(err, "loading hmac secret")
	}

	if !o.NoGitCredeentialsInit {
		err = o.InitGitConfigAndUser()
		if err != nil {
			return err
		}
	}

	if !o.NoRegisterWebHook {
		fullWebHookURL := util.UrlJoin(o.WebHookURL, o.Path)
		err = o.registerWebHook(fullWebHookURL, o.secret)
		if err != nil {
			return err
		}
	}

	mux := http.NewServeMux()
	mux.Handle("/health", http.HandlerFunc(o.health))
	mux.Handle("/ready", http.HandlerFunc(o.ready))

	indexPaths := []string{"/", "/index.html"}
	for _, p := range indexPaths {
		if o.Path != p {
			mux.Handle(p, http.HandlerFunc(o.getIndex))
		}
	}

	mux.Handle(o.Path, http.HandlerFunc(o.handleWebHookRequests))

	fmt.Sprintf("Environment Controller is now listening on %s for WebHooks from the source repository %s to trigger promotions", util.ColorInfo(util.UrlJoin(o.WebHookURL, o.Path)), util.ColorInfo(o.SourceURL))
	return http.ListenAndServe(":"+strconv.Itoa(o.Port), mux)
}

// health returns either HTTP 204 if the service is healthy, otherwise nothing ('cos it's dead).
func (o *ControllerEnvironmentOptions) health(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

// ready returns either HTTP 204 if the service is ready to serve requests, otherwise HTTP 503.
func (o *ControllerEnvironmentOptions) ready(w http.ResponseWriter, r *http.Request) {
	if o.isReady() {
		w.WriteHeader(http.StatusNoContent)
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
}

func (o *ControllerEnvironmentOptions) returnError(err error, message string, w http.ResponseWriter, r *http.Request) {
	log.Logger().Errorf("returning error: %v %s", err, message)
	responseHTTPError(w, http.StatusInternalServerError, "500 Internal Error: "+message+" "+err.Error())
}

// getIndex returns a simple home page
func (o *ControllerEnvironmentOptions) getIndex(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(helloMessage))
}


func (o *ControllerEnvironmentOptions) doHelmApply(dir string, w http.ResponseWriter, r *http.Request) (string, error) {
	runner := &util.Command{
		Args: []string {"step", "helm", "apply"},
		Name: "envctl",
		Dir:  dir,
	}

	return runner.RunWithoutRetry()
}

func (o *ControllerEnvironmentOptions) doUpdate(w http.ResponseWriter, r *http.Request) {
	if o.Dir == "" {
		dir, err := os.Getwd()
		if err != nil {
			o.returnError(err, err.Error(), w, r)
		}
		o.Dir = dir
	}

	o.BatchMode = true
	provider, err := o.GitProviderForURL(o.SourceURL, "git username")
	if err != nil {
		o.returnError(err, err.Error(), w, r)
	}
	dir, baseRef, upstreamInfo, forkInfo, err := gits.ForkAndPullRepo(o.SourceURL, o.Dir, o.Branch, "master", provider, o.Git(), "")
	if err != nil {
		o.returnError(err, err.Error(), w, r)
	}

	// Output the directory so it can be used in a script
	// Must use fmt.Print() as we need to write to stdout
	fmt.Print(dir)

	if forkInfo != nil {
		log.Logger().Infof("Forked %s to %s, pulled it into %s and checked out %s", util.ColorInfo(upstreamInfo.HTMLURL), util.ColorInfo(forkInfo.HTMLURL), util.ColorInfo(dir), util.ColorInfo(baseRef))
	} else {
		log.Logger().Infof("Pulled %s (%s) into %s", upstreamInfo.URL, baseRef, dir)
	}
	output, err := o.doHelmApply(dir, w, r)
	if err != nil {
		log.Logger().Infof("helm apply error: %s", output)
		o.returnError(err, err.Error(), w, r)
	}
	w.Write([]byte("OK"))
}

func (o *ControllerEnvironmentOptions) startPipelineRun(w http.ResponseWriter, r *http.Request) {
	o.doUpdate(w,r)
}


// discoverWebHookURL lets try discover the webhook URL from the Service
func (o *ControllerEnvironmentOptions) discoverWebHookURL() (string, error) {
	kubeCtl, ns, err := o.KubeClientAndNamespace()
	if err != nil {
		return "", err
	}
	serviceInterface := kubeCtl.CoreV1().Services(ns)
	svc, err := serviceInterface.Get(environmentControllerService, metav1.GetOptions{})
	if err != nil {
		return "", errors.Wrapf(err, "failed to find Service %s in namespace %s", environmentControllerService, ns)
	}
	u := services.GetServiceURL(svc)
	if u != "" {
		return u, nil
	}
	if svc.Spec.Type == corev1.ServiceTypeLoadBalancer {
		// lets wait for the LoadBalancer to be resolved
		loggedWait := false
		fn := func() (bool, error) {
			svc, err := serviceInterface.Get(environmentControllerService, metav1.GetOptions{})
			if err != nil {
				return false, err
			}
			u = services.GetServiceURL(svc)
			if u != "" {
				return true, nil
			}

			if !loggedWait {
				loggedWait = true
				fmt.Sprintf("waiting for the external IP on the service %s in namespace %s ...", environmentControllerService, ns)
			}
			return false, nil
		}
		err = o.RetryUntilTrueOrTimeout(time.Minute*5, time.Second*3, fn)
		if u != "" {
			return u, nil
		}
		if err != nil {
			return "", err
		}
	}
	return "", fmt.Errorf("could not find external URL of Service %s in namespace %s", environmentControllerService, ns)
}

// loadOrCreateHmacSecret loads the hmac secret
func (o *ControllerEnvironmentOptions) loadOrCreateHmacSecret() ([]byte, error) {
	kubeCtl, ns, err := o.KubeClientAndNamespace()
	if err != nil {
		return nil, err
	}
	secretInterface := kubeCtl.CoreV1().Secrets(ns)
	secret, err := secretInterface.Get(environmentControllerHmacSecret, metav1.GetOptions{})
	if err == nil {
		if secret.Data == nil || len(secret.Data[environmentControllerHmacSecretKey]) == 0 {
			// lets update the secret with a valid hmac token
			err = o.ensureHmacTokenPopulated()
			if err != nil {
				return nil, err
			}
			if secret.Data == nil {
				secret.Data = map[string][]byte{}
			}
			secret.Data[environmentControllerHmacSecretKey] = []byte(o.HMACToken)
			secret, err = secretInterface.Update(secret)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to update HMAC token secret %s in namespace %s", environmentControllerHmacSecret, ns)
			}
		}
	} else {
		err = o.ensureHmacTokenPopulated()
		if err != nil {
			return nil, err
		}
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: environmentControllerHmacSecret,
			},
			Data: map[string][]byte{
				environmentControllerHmacSecretKey: []byte(o.HMACToken),
			},
		}
		secret, err = secretInterface.Create(secret)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to create HMAC token secret %s in namespace %s", environmentControllerHmacSecret, ns)
		}
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("no Secret %s found in namespace %s", environmentControllerHmacSecret, ns)
	}
	return secret.Data[environmentControllerHmacSecretKey], nil
}

func (o *ControllerEnvironmentOptions) ensureHmacTokenPopulated() error {
	if o.HMACToken == "" {
		var err error
		// why 41?  seems all examples so far have a random token of 41 chars
		o.HMACToken, err = util.RandStringBytesMaskImprSrc(41)
		if err != nil {
			return errors.Wrapf(err, "failed to generate hmac token")
		}
	}
	return nil
}

func (o *ControllerEnvironmentOptions) isReady() bool {
	// TODO a better readiness check
	return true
}

func (o *ControllerEnvironmentOptions) unmarshalBody(w http.ResponseWriter, r *http.Request, result interface{}) error {
	// TODO assume JSON for now
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return errors.Wrap(err, "reading the JSON request body")
	}
	err = json.Unmarshal(data, result)
	if err != nil {
		return errors.Wrap(err, "unmarshalling the JSON request body")
	}
	return nil
}

func (o *ControllerEnvironmentOptions) marshalPayload(w http.ResponseWriter, r *http.Request, payload interface{}) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return errors.Wrapf(err, "marshalling the JSON payload %#v", payload)
	}
	w.WriteHeader(http.StatusOK)
	w.Write(data)

	fmt.Sprintf("completed request successfully and returned: %s", string(data))
	return nil
}



// handle request for pipeline runs
func (o *ControllerEnvironmentOptions) handleWebHookRequests(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		// liveness probe etc
		fmt.Sprintf("webhook handler not post mothod")
		o.getIndex(w, r)
		return
	}

	go o.startPipelineRun(w, r)
}

func (o *ControllerEnvironmentOptions) registerWebHook(webhookURL string, secret []byte) error {
	gitURL := o.SourceURL
	fmt.Sprintf("verifying that the webhook is registered for the git repository %s", util.ColorInfo(gitURL))

	var provider gits.GitProvider
	var err error

	if o.GitKind != "" {
		gitInfo, err := gits.ParseGitURL(gitURL)
		if err != nil {
			return err
		}
		gitHostURL := gitInfo.HostURL()

		provider, err = o.GitProviderForGitServerURL(gitHostURL, o.GitKind)
		if err != nil {
			return errors.Wrapf(err, "failed to create git provider for git URL %s kind %s", gitHostURL, o.GitKind)
		}
	} else {
		provider, err = o.GitProviderForURL(gitURL, "creating webhook git provider")
		if err != nil {
			return errors.Wrapf(err, "failed to create git provider for git URL %s", gitURL)
		}
	}
	fmt.Sprintf("Regist git web hoot arguments owner: %s repo %s webhookUrl %s secret %s", o.GitOwner, o.GitRepo, webhookURL, string(secret))
	webHookData := &gits.GitWebHookArguments{
		Owner: o.GitOwner,
		Repo: &gits.GitRepository{
			Name: o.GitRepo,
		},
		URL:    webhookURL,
		Secret: string(secret),
	}
	err = provider.CreateWebHook(webHookData)
	if err != nil {
		return errors.Wrapf(err, "failed to create git WebHook provider for URL %s", gitURL)
	}
	return nil
}


func responseHTTPError(w http.ResponseWriter, statusCode int, response string) {
	logrus.WithFields(logrus.Fields{
		"response":    response,
		"status-code": statusCode,
	}).Info(response)
	http.Error(w, response, statusCode)
}
