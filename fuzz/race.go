// +build race

package main

import (
	"io/ioutil"
	"log"
	"path/filepath"

	"go.starlark.net/repl"
	"go.starlark.net/resolve"
	"go.starlark.net/starlark"
)

func main() {
	files, err := filepath.Glob("./corpus/*")
	if err != nil {
		log.Fatal(err)
	}

	progs := make([][]byte, len(files))
	for i, f := range files {
		data, err := ioutil.ReadFile(f)
		if err != nil {
			log.Fatal(err)
		}
		if len(data) > 0 {
			data = data[1:]
		}
		progs[i] = data
	}

	resolve.AllowFloat = true
	resolve.AllowSet = true
	resolve.AllowLambda = true
	resolve.AllowNestedDef = true
	resolve.AllowBitwise = true
	resolve.AllowGlobalReassign = true
	resolve.AllowRecursion = true

	for _, data := range progs {
		go func(prog []byte) {
			for {
				thread := &starlark.Thread{Load: repl.MakeLoad()}
				var globals starlark.StringDict
				_, mod, err := starlark.SourceProgram("race.star", prog, globals.Has)
				if err != nil {
					continue
				}

				g, err := mod.Init(thread, nil)
				if err != nil {
					continue
				}
				g.Freeze()
			}
		}(data)
	}

	select {}
}
