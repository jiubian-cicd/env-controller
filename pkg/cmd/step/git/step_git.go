package git

import (
	"fmt"
	"github.com/jiubian-cicd/env-controller/pkg/cmd/helper"
	"github.com/spf13/cobra"

	"github.com/jiubian-cicd/env-controller/pkg/cmd/opts"
	"github.com/jiubian-cicd/env-controller/pkg/util"
)

// StepGitOptions contains the command line flags
type StepGitOptions struct {
	opts.StepOptions
}

// NewCmdStepGit Steps a command object for the "step" command
func NewCmdStepGit(commonOpts *opts.CommonOptions) *cobra.Command {
	options := &StepGitOptions{
		StepOptions: opts.StepOptions{
			CommonOptions: commonOpts,
		},
	}

	cmd := &cobra.Command{
		Use:   "git",
		Short: "git [command]",
		Run: func(cmd *cobra.Command, args []string) {
			options.Cmd = cmd
			options.Args = args
			err := options.Run()
			helper.CheckErr(err)
		},
	}
	cmd.AddCommand(NewCmdStepGitCredentials(commonOpts))
	cmd.AddCommand(NewCmdStepGitEnvs(commonOpts))
	cmd.AddCommand(NewCmdStepGitMerge(commonOpts))
	cmd.AddCommand(NewCmdStepGitForkAndClone(commonOpts))
	cmd.AddCommand(NewCmdStepGitValidate(commonOpts))
	cmd.AddCommand(NewCmdStepGitClose(commonOpts))
	return cmd
}

// Run implements this command
func (o *StepGitOptions) Run() error {
	return o.Cmd.Help()
}

func (o *StepGitOptions) dropRepositories(repoIds []string, message string) error {
	var answer error
	for _, repoId := range repoIds {
		err := o.dropRepository(repoId, message)
		if err != nil {
			fmt.Println("Failed to drop repository %s: %s", util.ColorInfo(repoIds), util.ColorError(err))
			if answer == nil {
				answer = err
			}
		}
	}
	return answer
}

func (o *StepGitOptions) dropRepository(repoId string, message string) error {
	if repoId == "" {
		return nil
	}
	fmt.Println("Dropping nexus release repository %s", util.ColorInfo(repoId))
	err := o.RunCommand("mvn",
		"org.sonatype.plugins:nexus-staging-maven-plugin:1.6.5:rc-drop",
		"-DserverId=oss-sonatype-staging",
		"-DnexusUrl=https://oss.sonatype.org",
		"-DstagingRepositoryId="+repoId,
		"-Ddescription=\""+message+"\" -DstagingProgressTimeoutMinutes=60")
	if err != nil {
		fmt.Println("Failed to drop repository %s due to: %s", repoId, err)
	} else {
		fmt.Println("Dropped repository %s", util.ColorInfo(repoId))
	}
	return err
}

func (o *StepGitOptions) releaseRepository(repoId string) error {
	if repoId == "" {
		return nil
	}
	fmt.Println("Releasing nexus release repository %s", util.ColorInfo(repoId))
	options := o
	err := options.RunCommand("mvn",
		"org.sonatype.plugins:nexus-staging-maven-plugin:1.6.5:rc-release",
		"-DserverId=oss-sonatype-staging",
		"-DnexusUrl=https://oss.sonatype.org",
		"-DstagingRepositoryId="+repoId,
		"-Ddescription=\"Next release is ready\" -DstagingProgressTimeoutMinutes=60")
	if err != nil {
		fmt.Println("Failed to release repository %s due to: %s", repoId, err)
	} else {
		fmt.Println("Released repository %s", util.ColorInfo(repoId))
	}
	return err
}
