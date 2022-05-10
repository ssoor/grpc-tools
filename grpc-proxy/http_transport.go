package grpc_proxy

import (
	"encoding/json"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

type HTTPTransport struct {
	*http.Transport

	// Our HAR log.
	// Starting size of 1000 entries, enlarged if necessary
	// Read the specification here: http://www.softwareishard.com/blog/har-12-spec/
	Har     Har
	harFile string
}

func NewHTTPTransport(transport *http.Transport, harFile string) *HTTPTransport {
	return &HTTPTransport{
		Har: Har{
			Log: newHarLog(),
		},
		harFile:   harFile,
		Transport: transport,
	}
}

func (m *HTTPTransport) create502Response(req *http.Request, err error) (resp *http.Response) {
	resp = &http.Response{
		StatusCode: http.StatusBadGateway,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Request:    req,
		Header: http.Header{
			"X-Request-Error": []string{err.Error()},
		},
		ContentLength:    0,
		TransferEncoding: nil,
		Body:             ioutil.NopCloser(strings.NewReader("")),
		Close:            true,
	}

	return
}

func fillIpAddress(req *http.Request, harEntry *HarEntry) {
	host, _, err := net.SplitHostPort(req.URL.Host)
	if err != nil {
		host = req.URL.Host
	}
	if ip := net.ParseIP(host); ip != nil {
		harEntry.ServerIpAddress = string(ip)
	}

	if ipaddr, err := net.LookupIP(host); err == nil {
		for _, ip := range ipaddr {
			if ip.To4() != nil {
				harEntry.ServerIpAddress = ip.String()
				return
			}
		}
	}
}

func (m *HTTPTransport) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	tranpoort := m.Transport

	req.Header.Set("Accept-Encoding", "gzip, deflate") // golang http response once support gzip

	st := time.Now()
	harEntry := new(HarEntry)
	harEntry.Request = parseRequest(req)
	harEntry.StartedDateTime = HarTime(st)

	resp, err = tranpoort.RoundTrip(req)
	if err != nil {
		log.Warning("tranpoort round trip:", req.URL.String(), ", err:", err)

		return m.create502Response(req, err), nil
	}

	harEntry.Timings.Send = float64(time.Since(st) / time.Millisecond)

	rst := time.Now()
	harEntry.Response = parseResponse(resp)
	harEntry.Timings.Receive = float64(time.Since(rst) / time.Millisecond)

	// 总时长
	harEntry.Time = float64(time.Since(time.Time(harEntry.StartedDateTime)) / time.Millisecond)

	if m.harFile != "" {
		fillIpAddress(req, harEntry)
		m.Har.Log.addEntry(*harEntry)

		str, _ := json.Marshal(m.Har)
		ioutil.WriteFile(m.harFile, str, 0644)
	}

	resp.Header.Del("Webkit-CSP")
	resp.Header.Del("Content-Security-Policy")

	resp.Header.Del("X-Webkit-CSP")
	resp.Header.Del("X-Content-Security-Policy")

	contentSecurityPolicy := "default-src * blob: data: 'unsafe-inline' 'unsafe-eval';" // script-src 'unsafe-eval';script-src 'unsafe-inline';

	resp.Header.Add("Webkit-CSP", contentSecurityPolicy)
	resp.Header.Add("Content-Security-Policy", contentSecurityPolicy)

	resp.Header.Add("X-Webkit-CSP", contentSecurityPolicy)
	resp.Header.Add("X-Content-Security-Policy", contentSecurityPolicy)

	return
}
