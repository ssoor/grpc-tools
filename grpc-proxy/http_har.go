package grpc_proxy

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var startingEntrySize int = 1000

type Har struct {
	Log HarLog `json:"log"`
}

type HarLog struct {
	Version string     `json:"version"`
	Creator HarCreator `json:"creator"`
	Pages   []HarPage  `json:"pages"`
	Entries []HarEntry `json:"entries"`
}

type HarCreator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type HarCache struct {
	AfterRequest  *HarAfterRequest  `json:"afterRequest,omitempty"`
	BeforeRequest *HarBeforeRequest `json:"beforeRequest,omitempty"`
}

type HarBeforeRequest struct {
	Expires    string `json:"expires"`
	LastAccess string `json:"lastAccess"`
	ETag       string `json:"eTag"`
	HitCount   int    `json:"hitCount"`
	Comment    string `json:"comment"`
}
type HarAfterRequest struct {
	Expires    string `json:"expires"`
	LastAccess string `json:"lastAccess"`
	ETag       string `json:"eTag"`
	HitCount   int    `json:"hitCount"`
	Comment    string `json:"comment"`
}

func newHarLog() HarLog {
	harLog := HarLog{
		Version: "1.2",
		Creator: HarCreator{
			Name:    "GoHarProxy",
			Version: "0.1",
		},
		Pages:   []HarPage{},
		Entries: makeNewEntries(),
	}
	return harLog
}

func (harLog *HarLog) addEntry(entry ...HarEntry) {
	entries := harLog.Entries
	m := len(entries)
	n := m + len(entry)
	if n > cap(entries) { // if necessary, reallocate
		// allocate double what's needed, for future growth.
		newEntries := make([]HarEntry, (n+1)*2)
		copy(newEntries, entries)
		entries = newEntries
	}
	entries = entries[0:n]
	copy(entries[m:n], entry)
	harLog.Entries = entries
	log.Println("Added entry ", entry[0].Request.Url)
}

func makeNewEntries() []HarEntry {
	return make([]HarEntry, 0, startingEntrySize)
}

type HarTime time.Time

func (m HarTime) String() string {
	return time.Time(m).Format("2006-01-02T15:04:05.999Z07:00")
}

func (m HarTime) MarshalJSON() ([]byte, error) {
	format := "2006-01-02T15:04:05.999Z07:00"

	b := make([]byte, 0, len(format)+2)
	b = append(b, '"')
	b = time.Time(m).AppendFormat(b, format)
	b = append(b, '"')

	return b, nil
}

type HarPage struct {
	Id              string         `json:"id"`
	Title           string         `json:"title"`
	PageTimings     HarPageTimings `json:"pageTimings"`
	StartedDateTime HarTime        `json:"startedDateTime"`
}

type HarEntry struct {
	Cache           HarCache     `json:"cache"`
	ServerIPAddress string       `json:"serverIPAddress"`
	PageRef         string       `json:"pageRef"`
	StartedDateTime HarTime      `json:"startedDateTime"`
	Time            float64      `json:"time"`
	Request         *HarRequest  `json:"request"`
	Response        *HarResponse `json:"response"`
	Timings         HarTimings   `json:"timings"`
	ServerIpAddress string       `json:"serverIpAddress"`
	Connection      string       `json:"connection"`
}

type HarRequest struct {
	Method      string             `json:"method"`
	Url         string             `json:"url"`
	HttpVersion string             `json:"httpVersion"`
	Cookies     []HarCookie        `json:"cookies"`
	Headers     []HarNameValuePair `json:"headers"`
	QueryString []HarNameValuePair `json:"queryString"`
	PostData    *HarPostData       `json:"postData"`
	BodySize    int64              `json:"bodySize"`
	HeadersSize int64              `json:"headersSize"`
}

var captureContent bool = true

func parseRequest(req *http.Request) *HarRequest {
	if req == nil {
		return nil
	}
	harRequest := HarRequest{
		Method:      req.Method,
		Url:         req.URL.String(),
		HttpVersion: req.Proto,
		Cookies:     parseCookies(req.Cookies()),
		Headers:     parseStringArrMap(req.Header),
		QueryString: parseStringArrMap((req.URL.Query())),
		BodySize:    req.ContentLength,
		HeadersSize: calcHeaderSize(req.Header),
	}

	if captureContent && (req.Method == "POST" || req.Method == "PUT") {
		harRequest.PostData = parsePostData(req)
	}

	return &harRequest
}

func calcHeaderSize(header http.Header) int64 {
	headerSize := 0
	for headerName, headerValues := range header {
		headerSize += len(headerName) + 2
		for _, v := range headerValues {
			headerSize += len(v)
		}
	}
	return int64(headerSize)
}

func parsePostData(req *http.Request) *HarPostData {
	defer func() {
		if e := recover(); e != nil {
			log.Printf("Error parsing request to %v: %v\n", req.URL, e)
		}
	}()

	harPostData := &HarPostData{
		Params:   []HarPostDataParam{},
		MimeType: req.Header.Get("Content-Type"),
	}

	if len(req.PostForm) > 0 {
		for k, v := range req.PostForm {
			param := HarPostDataParam{
				Name:  k,
				Value: strings.Join(v, ","),
			}

			harPostData.Params = append(harPostData.Params, param)
		}
	}

	if req.Body != nil {
		body := bytes.NewBuffer(nil)
		str, _ := ioutil.ReadAll(io.TeeReader(req.Body, body))

		req.Body.Close()
		req.Body = io.NopCloser(body)

		harPostData.Text = string(str)
	}

	return harPostData
}

func parseStringArrMap(stringArrMap map[string][]string) []HarNameValuePair {
	index := 0
	harQueryString := make([]HarNameValuePair, len(stringArrMap))
	for k, v := range stringArrMap {
		escapedKey, _ := url.QueryUnescape(k)
		escapedValues, _ := url.QueryUnescape(strings.Join(v, ","))
		harNameValuePair := HarNameValuePair{
			Name:  escapedKey,
			Value: escapedValues,
		}
		harQueryString[index] = harNameValuePair
		index++
	}
	return harQueryString
}

func parseCookies(cookies []*http.Cookie) []HarCookie {
	harCookies := make([]HarCookie, len(cookies))
	for i, cookie := range cookies {
		harCookie := HarCookie{
			Name:     cookie.Name,
			Domain:   cookie.Domain,
			Expires:  cookie.Expires,
			HttpOnly: cookie.HttpOnly,
			Path:     cookie.Path,
			Secure:   cookie.Secure,
			Value:    cookie.Value,
		}
		harCookies[i] = harCookie
	}
	return harCookies
}

type HarResponse struct {
	Status      int                `json:"status"`
	StatusText  string             `json:"statusText"`
	HttpVersion string             `json:"httpVersion"`
	Cookies     []HarCookie        `json:"cookies"`
	Headers     []HarNameValuePair `json:"headers"`
	Content     *HarContent        `json:"content"`
	RedirectUrl string             `json:"redirectURL"`
	BodySize    int64              `json:"bodySize"`
	HeadersSize int64              `json:"headersSize"`
}

func parseResponse(resp *http.Response) *HarResponse {
	defer func() {
		if e := recover(); e != nil {
			log.Printf("Error parsing response to %v: %v\n", resp.Request.URL, e)
		}
	}()

	if resp == nil {
		return nil
	}

	header := resp.Header.Clone()
	decodeBody := bytes.NewBuffer(nil)

	if resp.Body != nil {
		var read io.Reader
		var body *bytes.Buffer = bytes.NewBuffer(nil)

		switch strings.ToLower(header.Get("Content-Encoding")) {
		case "gzip":
			var err error
			read, err = gzip.NewReader(io.TeeReader(resp.Body, body))
			if nil != err {
				panic(fmt.Sprint("create gzip reader error:", err))
			}
		case "deflate":
			read = flate.NewReader(io.TeeReader(resp.Body, body))
		default:
			read = io.TeeReader(resp.Body, body)
		}

		decodeBody.ReadFrom(read)

		resp.Body.Close()
		resp.Body = io.NopCloser(body)
	}

	harResponse := HarResponse{
		Status:      resp.StatusCode,
		StatusText:  resp.Status,
		HttpVersion: resp.Proto,
		Cookies:     parseCookies(resp.Cookies()),
		Headers:     parseStringArrMap(header),
		RedirectUrl: "",
		BodySize:    resp.ContentLength,
		HeadersSize: calcHeaderSize(header),
	}

	if captureContent {
		harContent := HarContent{
			Text:     decodeBody.String(),
			Size:     int64(decodeBody.Len()),
			MimeType: resp.Header.Get("Content-Type"),
		}

		harResponse.Content = &harContent
	}

	return &harResponse
}

type HarCookie struct {
	Name     string    `json:"name"`
	Value    string    `json:"value"`
	Path     string    `json:"path"`
	Domain   string    `json:"domain"`
	Expires  time.Time `json:"expires"`
	HttpOnly bool      `json:"httpOnly"`
	Secure   bool      `json:"secure"`
}

type HarNameValuePair struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type HarPostData struct {
	MimeType string             `json:"mimeType"`
	Params   []HarPostDataParam `json:"params"`
	Text     string             `json:"text"`
}

type HarPostDataParam struct {
	Name        string `json:"name"`
	Value       string `json:"value"`
	FileName    string `json:"fileName"`
	ContentType string `json:"contentType"`
}

type HarContent struct {
	Size        int64  `json:"size"`
	Compression int64  `json:"compression"`
	MimeType    string `json:"mimeType"`
	Text        string `json:"text"`
	Encoding    string `json:"encoding"`
}

type HarPageTimings struct {
	OnLoad        float64 `json:"onLoad"`
	OnContentLoad float64 `json:"onContentLoad"`
}

type HarTimings struct {
	Blocked float64 `json:"blocked,omitempty"`
	Dns     float64 `json:"dns,omitempty"`
	Ssl     float64 `json:"ssl,omitempty"`
	Connect float64 `json:"connect,omitempty"`
	Send    float64 `json:"send"`
	Wait    float64 `json:"wait"`
	Receive float64 `json:"receive"`
}
