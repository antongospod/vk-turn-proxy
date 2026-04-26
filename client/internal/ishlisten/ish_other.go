//go:build !(linux && 386)

package ishlisten

import "net"

// Wrap is a no-op for architectures that don't need the legacy socketcall accept bypass.
func Wrap(ln net.Listener) (net.Listener, error) {
	return ln, nil
}
