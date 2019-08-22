package main

import (
	"github.com/jiubian-cicd/env-controller/pkg/cmd"
	"github.com/jiubian-cicd/env-controller/pkg/cmd/clients"
	"os"
)


// Run runs the command, if args are not nil they will be set on the command
func Run(args []string) error {
	cmd := cmd.NewENVCommand(clients.NewFactory(), os.Stdin, os.Stdout, os.Stderr, nil)
	if args != nil {
		args = args[1:]
		cmd.SetArgs(args)
	}
	return cmd.Execute()
}

func main() {
	Run(nil)
}