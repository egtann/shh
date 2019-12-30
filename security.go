// +build !openbsd

package main

// pledge is only supported on OpenBSD.
func pledge(promises, execPromises string) {}

// unveil is only supported on OpenBSD.
func unveil(filepath, perm string) {}
