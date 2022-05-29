package tlsmux

import (
	"net"
	"regexp"
	"time"
)

type ListenerOptions func(l *listener)

// If the return value net.Conn is null, intercepts the connection
type ListenerMiddleware func(net.Conn) (net.Conn, error)

func WithPeekConn() func(l *listener) {
	return func(l *listener) {
		l.features.peekConn.enable = true
	}
}

func WithTLSMiddleware(middle ListenerMiddleware, timeout time.Duration) func(l *listener) {
	var (
		peekSizes   = []int{3}
		peekPattern = regexp.MustCompile(`^\x16\x03[\x00-\x04]`) // TLS handshake byte + version number
	)

	return WithPatternMiddleware(peekPattern, peekSizes, timeout, middle)
}

func WithHTTPMiddleware(middle ListenerMiddleware, timeout time.Duration) func(l *listener) {
	var (
		peekSizes   = []int{4, 5, 6, 7, 8}
		peekPattern = regexp.MustCompile(`^(CONNECT)|(DELETE)|(GET)|(HEAD)|(OPTIONS)|(PATCH)|(POST)|(PUT)|(TRACE) `)
	)

	return WithPatternMiddleware(peekPattern, peekSizes, timeout, middle)
}

func WithPatternMiddleware(pattern *regexp.Regexp, peekSizes []int, timeout time.Duration, middle ListenerMiddleware) func(l *listener) {
	type patternConn struct {
		PeekConn
		t time.Time
	}

	return WithMiddleware(func(c net.Conn) (net.Conn, error) {
		if _, ok := c.(*patternConn); !ok {
			c = &patternConn{PeekConn: c.(PeekConn), t: time.Now()}
		}
		conn := c.(*patternConn)

		data := make([]byte, 8)
		for _, size := range peekSizes {
			if cap(data) < size {
				data = make([]byte, size)
			}

			var n int
			var err error

			deadline := conn.t.Add(timeout)
			for n < size && err == nil {
				n, err = conn.Peek(data[:size])

				// try only once
				if timeout == 0 {
					break
				}

				if time.Now().After(deadline) {
					// err = os.ErrDeadlineExceeded
					break
				}
			}

			// this is just a peek, so ignore any errors

			if n < size {
				return conn, nil
			}

			if pattern.Match(data) {
				return middle(conn)
			}
		}

		return conn, nil
	})
}

func WithMiddleware(middle ListenerMiddleware) func(l *listener) {
	return func(l *listener) {
		l.middles = append(l.middles, middle)
	}
}
