package main

import "fmt"

type emptyArgError struct{}

func (e *emptyArgError) Error() string {
	return "bad args"
}

type badArgError struct{ Arg string }

func (e *badArgError) Error() string {
	return fmt.Sprintf("unknown arg: %s", e.Arg)
}
