//go:build !linux

package dynscan

func LinuxRemoteEndpoints() map[string]struct{} {
	return map[string]struct{}{}
}
