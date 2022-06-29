package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
)

type Runner interface {
	Init([]string) error
	Run() error
	PrintUsage()
	Name() string
}

var cmds = []Runner{
	ClientSubCommand(),
}

func help() {
	fmt.Println("Egressinator")
	fmt.Println("Determine what ports are able to be use to egress a network")

	for _, r := range cmds {
		r.PrintUsage()
	}
}

func root(args []string) error {
	if len(args) < 1 {
		help()
		return errors.New("No subcommand specified")
	}

	subcommand := os.Args[1]

	for _, cmd := range cmds {
		if cmd.Name() == subcommand {
			err := cmd.Init(os.Args[2:])
			if err != nil {
				if err != flag.ErrHelp {
					fmt.Println("Error: ", err.Error())
					cmd.PrintUsage()
				}
				return nil
			}
			return cmd.Run()
		}
	}

	help()
	return fmt.Errorf("Unknown subcommand: %s", subcommand)
}

func main() {

	if err := root(os.Args[1:]); err != nil {
		log.Println(err)
		os.Exit(1)
	}

}
