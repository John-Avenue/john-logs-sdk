//go:build !windows

package johnlogs

import (
	"os"
	"syscall"
)

func lockFile(f *os.File) error   { return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) }
func unlockFile(f *os.File) error { return syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }

// fsync is fsync(2). On macOS that writes the file to the drive without
// F_FULLFSYNC's flush of the drive's whole cache.
func fsync(f *os.File) error { return syscall.Fsync(int(f.Fd())) }
