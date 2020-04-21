package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/cosmouser/hpi"
	"os"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprint(os.Stderr, "usage: hpiextract outdir files.hpi...\n")
		os.Exit(1)
	}
	parent := os.Args[1]
	if _, err := os.Stat(parent); os.IsNotExist(err) {
		err = os.MkdirAll(parent, 0744)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
	}
	for i := 2; i < len(os.Args); i++ {
		var header hpi.Header
		archive, err := os.Open(os.Args[i])
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
		if err := binary.Read(archive, binary.LittleEndian, &header); err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
		size := header.DirectorySize - header.Start
		key := header.GetKey()
		buf, err := hpi.ReadAndDecrypt(archive, key, int(size), int(header.Start))
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
		buf = append(make([]byte, int(header.Start)), buf...)
		directoryReader := bytes.NewReader(buf)
		err = hpi.TraverseTree(archive, directoryReader, key, parent, int(header.Start))
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
		archive.Close()
	}
}
