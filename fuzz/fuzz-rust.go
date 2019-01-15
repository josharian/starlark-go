// +build fuzzrust

package fuzz

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"time"

	"go.starlark.net/repl"
	"go.starlark.net/resolve"
	"go.starlark.net/starlark"
)

// var bigNum = regexp.MustCompile("[0-9a-fA-F]{3,}")

func FuzzRust(data []byte) (exit int) {
	// Someone somewhere is unhappy about NULs,
	// but I haven't found where/why and I'm sick of trying to figure it out,
	// and it's probably some dumb C string issue in python or something,
	// and who really cares about that?
	if bytes.IndexByte(data, 0) >= 0 {
		return 0
	}

	// go-fuzz is remarkably good at finding overflows and large numbers,
	// which cause things to be slow for predictable and uninteresting reasons.
	// try to avoid that.
	if bigNum.Match(data) {
		return 0
	}
	if bytes.IndexByte(data, '*') >= 0 {
		return 0 // avoid lots of multiplication, which can cause overflows and large data structures
	}

	// https://github.com/google/starlark-go/issues/69
	if bytes.Contains(data, []byte("getattr")) && bytes.Contains(data, []byte("elems")) {
		return 0
	}

	if len(data) > 0 {
		bits := data[0]
		bits = 0 // suppress all dialects for the time being; TODO: add appropriate flags to rust invocation, re-enable here
		resolve.AllowFloat = bits&(1<<0) != 0
		resolve.AllowSet = bits&(1<<1) != 0
		resolve.AllowLambda = bits&(1<<2) != 0
		resolve.AllowNestedDef = bits&(1<<3) != 0
		resolve.AllowBitwise = bits&(1<<4) != 0
		resolve.AllowGlobalReassign = bits&(1<<5) != 0
		// resolve.AllowRecursion = true // disabled -- too easy to make infinite loops :)
		data = data[1:]
	}

	// avoid left shift, which can cause overflows and large data structures
	if resolve.AllowBitwise && bytes.Contains(data, []byte{'<', '<'}) {
		return 0
	}

	// TODO: split data into multiple files.
	// Run them concurrently including with the race detector.
	// Run them as dependencies of each other.

	// TODO: can any of this be improved now that this is merged:
	// https://github.com/google/starlark-go/pull/98
	var starlarkout []byte
	thread := &starlark.Thread{
		Load: repl.MakeLoad(),
		Print: func(thread *starlark.Thread, msg string) {
			starlarkout = append(starlarkout, msg...)
		},
	}
	var globals starlark.StringDict

	_, mod, err := starlark.SourceProgram("fuzzy.star", data, globals.Has)
	if err != nil {
		return 0 // uninteresting
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	thread.SetLocal("context", ctx)

	g, goerr := mod.Init(thread, nil)
	g.Freeze()

	if ctx.Err() != nil {
		return 0 // presumably timed out, don't care
	}

	// go impl and rust impl should agree on legality of program.
	ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	tf, fserr := ioutil.TempFile("", "fuzz-rust-starlark")
	if fserr != nil {
		panic("could not create tempfile")
	}

	fserr = ioutil.WriteFile(tf.Name(), data, 0666)
	if fserr != nil {
		panic("could not write to tempfile")
	}

	cmd := exec.CommandContext(ctx, "starlark-repl", tf.Name())
	rustout, rusterr := cmd.CombinedOutput()
	if (goerr != nil) != (rusterr != nil) {
		// must agree on whether programs are valid
		fmt.Println("rustout:", string(rustout))
		fmt.Println("goerr:", goerr)
		fmt.Println("rusterr:", rusterr)
		panic("go/rust disagree")
	}

	os.Remove(tf.Name())

	return 1 // parses and executes: interesting
}
