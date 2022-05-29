package tlsmux

import (
	"net"
)

type ConnWarp interface {
	net.Conn
	// Return to original net.Conn
	Unwarp() net.Conn
}

type listener struct {
	net.Listener
	features struct {
		peekConn struct {
			enable bool
		}
	}
	middles []ListenerMiddleware
}

func NewListener(listen net.Listener, opts ...ListenerOptions) net.Listener {
	l := &listener{
		Listener: listen,
	}

	for _, opt := range opts {
		opt(l)
	}

	return l
}

func (m *listener) Accept() (net.Conn, error) {
	for {
		conn, err := m.Listener.Accept()
		if err != nil {
			return nil, err
		}

		if m.features.peekConn.enable {
			conn = PeekConn(NewPeekConn(conn))
		}

		for _, middle := range m.middles {
			conn, err = middle(conn)
			if err != nil {
				return nil, err
			}

			// skip this connection
			if conn == nil {
				break
			}
		}

		// skip this connection
		if conn == nil {
			continue
		}

		return conn, nil
	}
}
