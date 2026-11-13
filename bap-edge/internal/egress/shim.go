package egress

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
)

// ServeUnix serves the proxy on a unix socket (0600). The socket is the ONLY thing bind-mounted into a
// network-less sandbox, so the proxy is the sole way out. It returns a stop function.
func ServeUnix(p *Proxy, path string) (func(), error) {
	_ = os.Remove(path)
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	_ = os.Chmod(path, 0o600)
	srv := &http.Server{Handler: p}
	go func() { _ = srv.Serve(l) }()
	return func() { _ = srv.Close(); _ = os.Remove(path) }, nil
}

// Relay accepts TCP connections on listenAddr and pipes each to the unix socket. It runs INSIDE the
// sandbox so ordinary HTTP(S)_PROXY-aware tools can reach the socket. It returns the bound address.
func Relay(listenAddr, socket string) (net.Listener, error) {
	l, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, err
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				u, err := net.Dial("unix", socket)
				if err != nil {
					c.Close()
					return
				}
				go func() { defer u.Close(); defer c.Close(); _, _ = io.Copy(u, c) }()
				defer u.Close()
				defer c.Close()
				_, _ = io.Copy(c, u)
			}()
		}
	}()
	return l, nil
}

// RunShim is the in-sandbox entrypoint (`bap __shim -- cmd args`): start the relay on loopback, point the
// proxy environment at it, run the real command, return its exit status.
func RunShim(socket string, argv []string) (int, error) {
	if len(argv) == 0 {
		return 2, fmt.Errorf("shim: no command")
	}
	l, err := Relay("127.0.0.1:3128", socket)
	if err != nil {
		return 2, err
	}
	defer l.Close()
	env := os.Environ()
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
		env = append(env, k+"=http://"+l.Addr().String())
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode(), nil
		}
		return 127, err
	}
	return 0, nil
}
