//go:build ignore

// list-archive prints the entries of a task archive package (.tar.zst) so an operator can
// confirm which files a batch retained. Run: go run tools-archive-list.go <package>
package main

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/klauspost/compress/zstd"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: go run tools-archive-list.go <package.tar.zst> [filter]")
		os.Exit(2)
	}
	filter := ""
	if len(os.Args) > 2 {
		filter = os.Args[2]
	}
	file, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer file.Close()
	decoder, err := zstd.NewReader(file)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer decoder.Close()
	reader := tar.NewReader(decoder)
	total, matched := 0, 0
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		total++
		if filter == "" || strings.Contains(header.Name, filter) {
			matched++
			if matched <= 40 {
				fmt.Printf("%10d  %s\n", header.Size, header.Name)
			}
		}
	}
	fmt.Printf("entries=%d matched=%d\n", total, matched)
}
