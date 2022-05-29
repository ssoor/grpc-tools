package tlsmux

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"strconv"
	"sync"
	"syscall"

	"github.com/sirupsen/logrus"
)

// This file implements a listener that splits received connections
// into two listeners depending on whether the connection is (likely)
// a TLS connection. It does this by peeking at the first few bytes
// of the connection and seeing if it looks like a TLS handshake.

const (
	http2NextProtoTLS = "h2"
)

type CertificateGeter = func(serverName string) (*tls.Certificate, error)

type tlsMuxListener struct {
	net.Listener
	close *sync.Once
	conns <-chan net.Conn
	errs  <-chan error
}

func (c *tlsMuxListener) Accept() (net.Conn, error) {
	select {
	case conn := <-c.conns:
		return conn, nil
	case err := <-c.errs:
		return nil, err
	}
}

func (c *tlsMuxListener) Close() error {
	var err error
	c.close.Do(func() {
		err = c.Listener.Close()
	})
	return err
}

func New(logger logrus.FieldLogger, listener net.Listener, getCert CertificateGeter, tlsConfig tls.Config) (net.Listener, net.Listener) {
	var nonTLSConns = make(chan net.Conn, 128) // TODO decide on good buffer sizes for these channels
	var nonTLSErrs = make(chan error, 128)
	var tlsConns = make(chan net.Conn, 128)
	var tlsErrs = make(chan error, 128)

	opts := []ListenerOptions{
		WithPeekConn(),
		WithTLSMiddleware(func(c net.Conn) (net.Conn, error) {
			tlsConns <- c
			return nil, nil
		}, 0),
		WithHTTPMiddleware(func(c net.Conn) (net.Conn, error) {
			nonTLSConns <- c
			return nil, nil
		}, 0),
		WithMiddleware(func(c net.Conn) (net.Conn, error) {
			type proxiedConnection interface {
				OriginalDestination() (tls bool, addr string)
			}

			proxConn, ok := c.(proxiedConnection)
			if !ok {
				return c, nil
			}

			go func() {
				originalTls, originalAddr := proxConn.OriginalDestination()
				// cannot intercept so will just transparently proxy instead
				logger.Debugf("No certificate able to intercept connections to %s, proxying instead.", originalAddr)
				var err error
				var destConn net.Conn
				if originalTls {
					destConn, err = tls.Dial(c.LocalAddr().Network(), originalAddr, nil)
				} else {
					destConn, err = net.Dial(c.LocalAddr().Network(), originalAddr)
				}
				if err != nil {
					logger.WithError(err).Debugf("Failed proxying connection to %s, Error while dialing.", originalAddr)
					_ = c.Close()
					return
				}

				err = forwardConnection(c, destConn)
				if err != nil {
					logger.WithError(err).Warnf("Error proxying connection to %s.", originalAddr)
				}
			}()

			return nil, nil
		}),
	}

	hlisten := NewListener(listener, opts...)
	go func() {
		for {
			c, err := hlisten.Accept()
			if err != nil {
				nonTLSErrs <- err
				tlsErrs <- err
				continue
			}

			go func() {
				if err := handleConn(logger, c); err != nil {
					nonTLSErrs <- err
					tlsErrs <- err
				}
			}()

		}
	}()

	closer := &sync.Once{}
	nonTLSListener := &tlsMuxListener{
		Listener: listener,
		close:    closer,
		conns:    nonTLSConns,
	}

	// Support HTTP/2: https://golang.org/pkg/net/http/?m=all#Serve
	tlsConfig.NextProtos = append(tlsConfig.NextProtos, http2NextProtoTLS)
	tlsConfig.GetCertificate = func(clientHello *tls.ClientHelloInfo) (cert *tls.Certificate, err error) {
		return getCert(clientHello.ServerName)
	}

	tlsListener := tls.NewListener(&tlsMuxListener{
		Listener: listener,
		close:    closer,
		conns:    tlsConns,
	}, &tlsConfig)

	return nonTLSListener, tlsListener
}

func handleConn(logger logrus.FieldLogger, c net.Conn) error {
	originalAddr, err := getOriginalAddr(c)
	if err != nil {
		return err
	}

	// cannot intercept so will just transparently proxy instead
	logger.Debugf("No certificate able to intercept connections to %s, proxying instead.", originalAddr)
	destConn, err := net.Dial(c.LocalAddr().Network(), originalAddr)
	if err != nil {
		logger.WithError(err).Debugf("Failed proxying connection to %s, Error while dialing.", originalAddr)
		_ = c.Close()
		return err
	}

	err = forwardConnection(c, destConn)
	if err != nil {
		logger.WithError(err).Warnf("Error proxying connection to %s.", originalAddr)
	}

	return nil
}

func getOriginalAddr(c net.Conn) (string, error) {
	conn, ok := c.(interface {
		File() (f *os.File, err error)
	})
	if !ok {
		return "", errors.New("not a TCPConn")
	}

	file, err := conn.File()
	if err != nil {
		return "", err
	}
	defer file.Close()

	const SO_ORIGINAL_DST = 80
	addr, err := syscall.GetsockoptIPv6Mreq(int(file.Fd()), syscall.SOL_IP, SO_ORIGINAL_DST)
	if err != nil {
		return "", err
	}

	var ip net.IP
	switch binary.LittleEndian.Uint16(addr.Multiaddr[:2]) {
	case syscall.AF_INET:
		ip = addr.Multiaddr[4:8]
	default:
		return "", errors.New("unrecognized address family")
	}

	port := int(addr.Multiaddr[2])<<8 + int(addr.Multiaddr[3])

	return net.JoinHostPort(ip.String(), strconv.Itoa(port)), nil
}
