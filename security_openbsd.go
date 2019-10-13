package main

import "golang.org/x/sys/unix"

// pledge restricts shh to very limited syscalls.
func pledge(promises, execPromises string) {
	if err := unix.Pledge(promises, execPromises); err != nil {
		panic(err)
	}
}

// unveil restricts shh to very limited (read-only) filesystem access.
func unveil(filepath string, perm string) {
	if err := unix.Unveil(filepath, perm); err != nil {
		panic(err)
	}
}

func unveilBlock() {
	if err := unix.UnveilBlock(); err != nil {
		panic(err)
	}
}
