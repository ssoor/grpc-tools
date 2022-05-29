package tlsmux

import (
	"net"
)

type PeekConn interface {
	ConnWarp

	// Peek and return the length of the data you see
	Peek(b []byte) (int, error)
}

type peekConn struct {
	net.Conn
	peeked []byte
}

func NewPeekConn(c net.Conn) *peekConn {
	p := &peekConn{
		Conn: c,
	}
	return p
}

func (p *peekConn) Unwarp() net.Conn {
	return p.Conn
}

func (p *peekConn) Peek(b []byte) (n int, err error) {
	size := cap(b)

	if cap(p.peeked) < size {
		peek := make([]byte, 0, size)
		if p.peeked != nil {
			copy(peek, p.peeked)
		}

		p.peeked = peek
	}

	if len(p.peeked) < size {
		_, err = p.Conn.Read(p.peeked[len(p.peeked):size])
	}

	copy(b, p.peeked)
	return len(p.peeked), err
}

func (p *peekConn) Read(b []byte) (int, error) {
	if p.peeked == nil {
		return p.Conn.Read(b)
	}

	var size int
	var peek []byte

	size = len(b)
	if len(p.peeked) > size {
		peek = p.peeked[:size]
		p.peeked = p.peeked[size:]
	} else {
		peek = p.peeked
		p.peeked = nil
	}

	copy(b, peek)
	size = len(peek)
	n, err := p.Conn.Read(b[size:])

	return n + size, err
}
