package fuzz

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"time"
	"unicode/utf8"

	"go.starlark.net/repl"
	"go.starlark.net/resolve"
	"go.starlark.net/starlark"
)

var bigNum = regexp.MustCompile("[0-9a-fA-F]{3,}")

func Fuzz(data []byte) (exit int) {
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

	if len(data) > 0 {
		bits := data[0]
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

	if bytes.Contains(data, []byte("/dev/full")) {
		// Clever, go-fuzz.
		// If you run load("/dev/full", "a") on a linux machine,
		// you OOM trying to read an infinite-sized file into memory.
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

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	thread.SetLocal("context", ctx)

	g, err := mod.Init(thread, nil)
	g.Freeze()
	if err != nil {
		return 0
	}

	if ctx.Err() != nil {
		return 0 // presumably timed out, don't care
	}

	// Starlark accepted this program. Python had better too, since it is a superset of starlark.
	ctx, cancel = context.WithTimeout(ctx, 10*time.Second) // python is slower :)
	defer cancel()

	prog := string(data)
	cmd2 := exec.CommandContext(ctx, "python", "-c", prog)
	py2out, err2 := cmd2.CombinedOutput()
	if err2 != nil && ctx.Err() == nil {
		// Check whether python3 also rejects this code.
		cmd3 := exec.CommandContext(ctx, "python3", "-c", prog)
		py3out, err3 := cmd3.CombinedOutput()
		if err3 != nil && ctx.Err() == nil {
			// starlark accepts, python2 and python3 reject.
			// This is probably a bug. Except when it's not.

			// python evaluates enumerate lazily. starlark does not.
			// This leads them to disagree about whether enumerate is subscriptable.
			// python2 and python3 reject the following code, but starlark accepts it:
			//   enumerate(())[:]
			if bytes.Contains(data, []byte("enumerate")) {
				// https: //github.com/bazelbuild/starlark/issues/29
				return 0
			}

			if bytes.Contains(data, []byte("getattr")) || bytes.Contains(py3out, []byte("'str' object has no attribute ")) {
				reject := [...][]byte{
					[]byte("elems"), []byte("el\\ems"), []byte("codepoint_ords"), []byte("codepoints"),
				}
				for _, r := range &reject {
					if bytes.Contains(data, r) {
						return 0
					}
				}
				// Intentional:
				// https://github.com/google/starlark-go/issues/69
				return 0
			}

			// python2 eagerly rejects some expressions involving print, len, and dir.
			// python3 insists on sorted taking only one positional param.
			// starlark accepts a second positional param (like python2) and
			// lazily evaluates print/len/dir (like python3).
			// go-fuzz thus finds a way to pit python2 and python3 against each other,
			// each failing in their own way, while starlark succeeds.
			// Well done, go-fuzz...but no thanks.
			if bytes.Contains(data, []byte("sorted")) {
				reject := [...][]byte{
					[]byte("len"), []byte("int"),
					[]byte("dir"), []byte("print"),
					[]byte("type"), []byte("hash"),
					[]byte("bool"), []byte("list"),
					[]byte("repr"), []byte("max"),
					[]byte("min"),
				}
				for _, r := range &reject {
					if bytes.Contains(data, r) {
						return 0
					}
				}
				if bytes.Contains(py2out, []byte("comparison function must return int, not tuple")) {
					return 0
				}
				if bytes.Contains(py3out, []byte("must use keyword argument for key function")) {
					return 0
				}
			}

			if bytes.Contains(data, []byte("print")) &&
				bytes.Contains(py2out, []byte("SyntaxError: invalid syntax")) {
				// python2 eagerly rejects some print expressions.
				// go-fuzz is good at finding other expressions that python3 rejects but that python2 accepts.
				return 0
			}

			if bytes.Contains(py3out, []byte("int too large to convert to float")) {
				// starlark accepts gigantic numbers readily, but Python does not.
				// we managed to knock out a bunch of giant numbers above,
				// but not all of them.
				// This check might eventually need to be made more general.
				reject := [...][]byte{
					[]byte("int"), []byte("%f"), []byte("%f"),
				}
				for _, r := range &reject {
					if bytes.Contains(data, r) {
						return 0
					}
				}
				return 0
			}

			isascii := true
			for _, b := range data {
				if b > utf8.RuneSelf {
					isascii = false
					break
				}
			}
			if !isascii && bytes.Contains(py2out, []byte("invalid syntax")) {
				// Python 2 doesn't allow non-ascii identifiers.
				// This leads to spurious rejections.
				return 0
			}

			if bytes.Contains(py3out, []byte("surrogates not allowed")) {
				// Python 3's utf-8 encoder rejects unicode surrogates.
				// starlark accepts them.
				return 0
			}

			if bytes.Contains(data, []byte("in")) &&
				(bytes.Contains(py2out, []byte("unhashable")) ||
					bytes.Contains(py3out, []byte("unhashable"))) {
				// issue 113
				return 0
			}

			if bytes.Contains(py3out, []byte("'reversed' object is not subscriptable")) ||
				bytes.Contains(py3out, []byte("is not reversible")) {
				// https://github.com/bazelbuild/starlark/issues/29
				return 0
			}

			if bytes.Contains(py3out, []byte("'zip' object has no attribute 'clear'")) {
				// zip().clear
				// Python2 zip() returns a list, but Python2 lists don't have a clear function.
				// Python3 zip() returns a zip object.
				// starlark zip returns a list and has a clear function.
				return 0
			}

			if bytes.Contains(py2out, []byte("unsupported operand type")) &&
				bytes.Contains(py2out, []byte("'listreverseiterator'")) &&
				bytes.Contains(py2out, []byte("'list'")) {
				// https://github.com/bazelbuild/starlark/issues/29
				// starbug "reversed(zip())+zip()"
				// starbug "reversed(zip())*3"
				return 0
			}

			if bytes.Contains(py2out, []byte("invalid literal for int")) {
				// https://github.com/google/starlark-go/issues/130
				return 0
			}

			if bytes.Contains(py3out, []byte("can't assign to keyword")) {
				// https://github.com/google/starlark-go/issues/133
				return 0
			}

			if bytes.Contains(data, []byte("dir(")) {
				// This is a cute one:
				//   dict(dir(range))
				// In python, dir(range) has length 8, making it an invalid argument to dict.
				// In starlark, dir(range) has length 0, making it a valid argument to dict.
				// Avoid these shenanigans by skipping dir entirely. :/
				return 0
			}

			if bytes.Contains(py3out, []byte("invalid token")) &&
				!bytes.Contains(py2out, []byte("invalid token")) &&
				bytes.Contains(data, []byte("0")) {
				// go-fuzz likes to find cases in which python3 rejects an octal written like 0123
				// and python2 rejects the code for some other reason.
				// Example: "0%(3/04)"
				// We could make this check more precise, but hey, it's a start.
				return 0
			}

			if bytes.Contains(data, []byte("elem_ords")) {
				// starlark has elem_ords; python does not.
				return 0
			}

			if bytes.Contains(data, []byte("type")) {
				// In starlark, "type" returns a string; in Python, it returns a type type/class.
				// They can thus mismatch in any scenario where a string will do but others won't.
				// Examples:
				//   type(0).elems()
				//   type(0) in type(0)
				// Try to capture the various error messages that this can lead to.
				reject := [...][]byte{
					[]byte("type object"), []byte("argument of type 'type'"),
					[]byte(", type found"), []byte(", not type"),
					[]byte("subscriptable"),
				}
				for _, r := range &reject {
					if bytes.Contains(py3out, r) {
						return 0
					}
				}
			}

			fmt.Println("python2:")
			fmt.Println(string(py2out))
			fmt.Println(err2)
			fmt.Println("python3:")
			fmt.Println(err3)
			fmt.Println(string(py3out))
			panic(fmt.Sprintf("starlark accepted but python2/3 did not: %s", data))
		}
	}

	// TODO: compare with java skylark and starlark-rust

	return 1 // parses and executes: interesting
}
