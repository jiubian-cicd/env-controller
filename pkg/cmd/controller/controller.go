package controller

import (
	"github.com/jiubian-cicd/env-controller/pkg/cmd/opts"
	"github.com/spf13/cobra"

	"github.com/jiubian-cicd/env-controller/pkg/cmd/helper"
	"github.com/jiubian-cicd/env-controller/pkg/cmd/templates"
)

// ControllerOptions contains the CLI options
type ControllerOptions struct {
	*opts.CommonOptions
}

var (
	controllerLong = templates.LongDesc(`
		Runs a controller

`)

	controllerExample = templates.Examples(`
	`)
)

// NewCmdController creates the edit command
func NewCmdController(commonOpts *opts.CommonOptions) *cobra.Command {
	options := &ControllerOptions{
		commonOpts,
	}

	cmd := &cobra.Command{
		Use:     "controller <command> [flags]",
		Short:   "Runs a controller",
		Long:    controllerLong,
		Example: controllerExample,
		Run: func(cmd *cobra.Command, args []string) {
			options.Cmd = cmd
			options.Args = args
			err := options.Run()
			helper.CheckErr(err)
		},
	}

	cmd.AddCommand(NewCmdControllerEnvironment(commonOpts))
	return cmd
}

// Run implements this command
func (o *ControllerOptions) Run() error {
	return o.Cmd.Help()
}
