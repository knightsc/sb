package main

import (
	"flag"
	"log"
	"os"

	"github.com/knightsc/sb"
)

func main() {
	flInput := flag.String("i", "", "The path to the sandbox profile to compile")
	flOutput := flag.String("o", "", "The path to save the compiled sandbox profile")
	flag.Parse()

	if *flInput == "" || *flOutput == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	in, err := os.Open(*flInput)
	if err != nil {
		log.Fatalf("error: %s", err)
	}
	defer in.Close()

	out, err := os.Create(*flOutput)
	if err != nil {
		log.Fatalf("error: %s", err)
	}
	defer out.Close()

	err = sb.Compile(in, out)
	if err != nil {
		log.Fatalf("error: %s", err)
	}
}
