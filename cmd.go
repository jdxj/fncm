package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/panjf2000/ants/v2"
	"github.com/spf13/cobra"
)

var (
	ErrFindNCMFailed = errors.New("find *.ncm failed")
	ErrNotNCMFile    = errors.New("not ncm file")
	ErrNoNCMFile     = errors.New("no ncm file")
	ErrInvalidOutput = errors.New("invalid output")
)

var (
	rootCmd *cobra.Command
	gPool   *ants.Pool
)

var (
	input  *string
	output *string
	files  *[]string
)

func init() {
	rootCmd = NewRootCmd()
	gPool, _ = ants.NewPool(runtime.NumCPU())
}

func Execute() error {
	return rootCmd.Execute()
}

func NewRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:                        "fncm",
		Aliases:                    nil,
		SuggestFor:                 nil,
		Short:                      "",
		Long:                       "",
		Example:                    "",
		ValidArgs:                  nil,
		ValidArgsFunction:          nil,
		Args:                       nil,
		ArgAliases:                 nil,
		BashCompletionFunction:     "",
		Deprecated:                 "",
		Annotations:                nil,
		Version:                    "",
		PersistentPreRun:           nil,
		PersistentPreRunE:          nil,
		PreRun:                     nil,
		PreRunE:                    nil,
		Run:                        rootCmdRun,
		RunE:                       nil,
		PostRun:                    nil,
		PostRunE:                   nil,
		PersistentPostRun:          nil,
		PersistentPostRunE:         nil,
		FParseErrWhitelist:         cobra.FParseErrWhitelist{},
		CompletionOptions:          cobra.CompletionOptions{},
		TraverseChildren:           false,
		Hidden:                     false,
		SilenceErrors:              false,
		SilenceUsage:               false,
		DisableFlagParsing:         false,
		DisableAutoGenTag:          false,
		DisableFlagsInUseLine:      false,
		DisableSuggestions:         false,
		SuggestionsMinimumDistance: 0,
	}

	// flags
	flags := cmd.Flags()
	input = flags.StringP("input", "i", "", "specifies the path where the ncm file is located")
	files = flags.StringSliceP("file", "f", nil, "specifies a certain ncm file")
	output = flags.StringP("output", "o", "./", "specifies the path to save the decrypted result")
	return cmd
}

func rootCmdRun(cmd *cobra.Command, args []string) {
	inputFiles, err := getNCM(*input, *files)
	if err != nil {
		cmd.PrintErrln(err)
		return
	}

	err = checkOutput(*output)
	if err != nil {
		cmd.PrintErrln(err)
	}

	wg := sync.WaitGroup{}
	wg.Add(len(inputFiles))

	for p := range inputFiles {
		in := p
		err := gPool.Submit(func() {
			fn := NewFNcm(in, *output)
			err := fn.Decrypt()
			if err != nil {
				cmd.PrintErrln(err)
			} else {
				cmd.Printf("decrypt success: %s\n", in)
			}

			wg.Done()
		})
		if err != nil {
			cmd.PrintErrln(err)
		}
	}

	wg.Wait()
}

func getNCMFromDir(input string) ([]string, error) {
	if input == "" {
		return nil, nil
	}
	var inputFiles []string
	err := filepath.Walk(input, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if filepath.Ext(info.Name()) != ".ncm" {
			return nil
		}
		abs, err := filepath.Abs(path)
		if err != nil {
			return err
		}
		inputFiles = append(inputFiles, abs)
		return nil
	})
	return inputFiles, err
}

func getNCMFromFile(files []string) ([]string, error) {
	var inputFiles []string
	for _, v := range files {
		info, err := os.Stat(v)
		if err != nil {
			return nil, err
		}
		if info.IsDir() ||
			filepath.Ext(info.Name()) != ".ncm" {
			return nil, ErrNotNCMFile
		}
		fileAbs, err := filepath.Abs(v)
		if err != nil {
			return nil, err
		}
		inputFiles = append(inputFiles, fileAbs)
	}
	return inputFiles, nil
}

func getNCM(input string, files []string) (map[string]struct{}, error) {
	inputFiles := make(map[string]struct{})
	list, err := getNCMFromDir(input)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFindNCMFailed, err)
	}
	for _, v := range list {
		inputFiles[v] = struct{}{}
	}

	list, err = getNCMFromFile(files)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFindNCMFailed, err)
	}
	for _, v := range list {
		inputFiles[v] = struct{}{}
	}
	if len(inputFiles) == 0 {
		return nil, ErrNoNCMFile
	}
	return inputFiles, nil
}

func checkOutput(output string) error {
	info, err := os.Stat(output)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%w: %s", ErrInvalidOutput, info.Name())
	}
	return nil
}
