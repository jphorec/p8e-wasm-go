package command

import (
	"github.com/spf13/cobra"
)

func RootCmd() *cobra.Command {
	return &cobra.Command{
		Use: "p8e",
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}
}
