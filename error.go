package main

type emptyArgError struct{}

func (e emptyArgError) Error() string {
	return "bad args"
}
