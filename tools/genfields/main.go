// Command genfields renders docs/fields.md from the plugin's field table.
package main

import (
	"flag"
	"log"
	"os"
)

const filePerm = 0o644

func main() {
	out := flag.String("out", "docs/fields.md", "output file")
	flag.Parse()
	if err := os.WriteFile(*out, []byte(render()), filePerm); err != nil {
		log.Fatal(err)
	}
}
