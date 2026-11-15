package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var osExit = os.Exit

// RootCmd returns the generator: it reads the S-boxes from --sbox and writes
// the AVX2 kernels to --out and the AVX-512 kernels to --out512.
func RootCmd() *cobra.Command {
	var sboxPath, outPath, out512Path string
	cmd := &cobra.Command{
		Use:           "genavx2",
		Short:         "generate serpent_avx2_amd64.s and serpent_avx512_amd64.s with go-asmgen",
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			src, err := os.ReadFile(sboxPath)
			if err != nil {
				return err
			}
			text, err := Generate(src)
			if err != nil {
				return err
			}
			text512, err := GenerateAVX512()
			if err != nil {
				return err
			}
			for _, w := range []struct{ path, text string }{{outPath, text}, {out512Path, text512}} {
				if err := os.WriteFile(w.path, []byte(w.text), 0o644); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "wrote %s (%d bytes)\n", w.path, len(w.text))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&sboxPath, "sbox", "../../sbox.go", "the Go file holding the sboxE0..sboxD7 functions")
	cmd.Flags().StringVar(&outPath, "out", "../../serpent_avx2_amd64.s", "the AVX2 assembly file to write")
	cmd.Flags().StringVar(&out512Path, "out512", "../../serpent_avx512_amd64.s", "the AVX-512 assembly file to write")
	return cmd
}

func main() {
	cmd := RootCmd()
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(cmd.ErrOrStderr(), "genavx2:", err)
		osExit(1)
	}
}
