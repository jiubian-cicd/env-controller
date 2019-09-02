/*
Copyright 2018 The Kubernetes Authors & The Jenkins X Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cmd

import (
	"github.com/jiubian-cicd/env-controller/pkg/cmd/clients"
	"github.com/jiubian-cicd/env-controller/pkg/cmd/controller"
	"github.com/jiubian-cicd/env-controller/pkg/cmd/opts"
	"io"
	"strings"
	"github.com/spf13/cobra"
	"gopkg.in/AlecAivazis/survey.v1/terminal"
)


// NewJXCommand creates the `jx` command and its nested children.
// args used to determine binary plugin to run can be overridden (does not affect compiled in commands).
func NewENVCommand(f clients.Factory, in terminal.FileReader, out terminal.FileWriter,
	err io.Writer, args []string) *cobra.Command {
	rootCommand := &cobra.Command{
		Use:              "envctl",
		Short:            "envctl is a command line tool for working with helm or hydra",
		Run:              runHelp,
	}
	commonOpts := opts.NewCommonOptionsWithTerm(f, in, out, err)
	rootCommand.Version = "1.0"
	rootCommand.SetVersionTemplate("{{printf .Version}}\n")
	rootCommand.AddCommand(controller.NewCmdController(commonOpts), NewCmdStep(commonOpts))

	return rootCommand
}

func findCommands(subCommand string, commands ...*cobra.Command) []*cobra.Command {
	answer := []*cobra.Command{}
	for _, parent := range commands {
		for _, c := range parent.Commands() {
			if commandHasParentName(c, subCommand) {
				answer = append(answer, c)
			} else {
				childCommands := findCommands(subCommand, c)
				if len(childCommands) > 0 {
					answer = append(answer, childCommands...)
				}
			}
		}
	}
	return answer
}

func commandHasParentName(command *cobra.Command, name string) bool {
	path := fullPath(command)
	return strings.Contains(path, name)
}

func fullPath(command *cobra.Command) string {
	name := command.Name()
	parent := command.Parent()
	if parent != nil {
		return fullPath(parent) + " " + name
	}
	return name
}

func runHelp(cmd *cobra.Command, args []string) {
	cmd.Help()
}
