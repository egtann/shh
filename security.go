// +build !openbsd

package main

// pledge is only supported on OpenBSD.
func pledge(promises, execPromises string) error { return nil }

// unveil is only supported on OpenBSD.
func unveil() error { return nil }
