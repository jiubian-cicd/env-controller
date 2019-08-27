package cmd

import (
	"github.com/jiubian-cicd/env-controller/pkg/cmd/config"
	"github.com/jiubian-cicd/env-controller/pkg/cmd/helper"
	"github.com/jiubian-cicd/env-controller/pkg/cmd/opts"
	"github.com/jiubian-cicd/env-controller/pkg/cmd/step/helm"

	//"github.com/jiubian-cicd/env-controller/pkg/cmd/step"
	"github.com/jiubian-cicd/env-controller/pkg/cmd/step/git"
	//"github.com/jiubian-cicd/env-controller/pkg/cmd/step/helm"
	"github.com/spf13/cobra"
)

// NewCmdStep Steps a command object for the "step" command
func NewCmdStep(commonOpts *opts.CommonOptions) *cobra.Command {
	options := &opts.StepOptions{
		CommonOptions: commonOpts,
	}

	cmd := &cobra.Command{
		Use:     "step",
		Short:   "pipeline steps",
		Aliases: []string{"steps"},
		Run: func(cmd *cobra.Command, args []string) {
			options.Cmd = cmd
			options.Args = args
			err := options.Run()
			helper.CheckErr(err)
		},
	}


	cmd.AddCommand(git.NewCmdStepGit(commonOpts))
	cmd.AddCommand(config.NewCmdStepPatchConfigMap(commonOpts))
	cmd.AddCommand(helm.NewCmdStepHelm(commonOpts))
	return cmd
}
