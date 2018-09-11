package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/knightsc/sb"
)

func main() {
	flInput := flag.String("i", "", "The path to the compiled sandbox to decompile")
	flag.Parse()

	if *flInput == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	p, err := sb.Open(*flInput)
	if err != nil {
		log.Fatalf("error: %s", err)
	}
	defer p.Close()

	fmt.Printf("%#v", p)
}
