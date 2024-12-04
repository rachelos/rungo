// Copyright 2014 rungo Author. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package httplib is used as http.Client
// Usage:
//
// import "github.com/rachelos/rungo/client/httplib"
//
//	b := httplib.Post("http://rungo.vip/")
//	b.Param("username","astaxie")
//	b.Param("password","123456")
//	b.PostFile("uploadfile1", "httplib.pdf")
//	b.PostFile("uploadfile2", "httplib.txt")
//	str, err := b.String()
//	if err != nil {
//		t.Fatal(err)
//	}
//	fmt.Println(str)
package httplib

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/xml"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/rachelos/rungo/core/berror"
	"github.com/rachelos/rungo/core/logs"
)

const contentTypeKey = "Content-Type"

// it will be the last filter and execute request.Do
var doRequestFilter = func(ctx context.Context, req *RungoHTTPRequest) (*http.Response, error) {
	return req.doRequest(ctx)
}

// NewrungoRequest returns *RungoHTTPRequest with specific method
// TODO add error as return value
// I think if we don't return error
// users are hard to check whether we create rungo request successfully
func NewrungoRequest(rawurl, method string) *RungoHTTPRequest {
	return NewrungoRequestWithCtx(context.Background(), rawurl, method)
}

// NewrungoRequestWithCtx returns a new RungoHTTPRequest given a method, URL
func NewrungoRequestWithCtx(ctx context.Context, rawurl, method string) *RungoHTTPRequest {
	req, err := http.NewRequestWithContext(ctx, method, rawurl, nil)
	if err != nil {
		logs.Error("%+v", berror.Wrapf(err, InvalidURLOrMethod, "invalid raw url or method: %s %s", rawurl, method))
	}
	return &RungoHTTPRequest{
		url:     rawurl,
		req:     req,
		params:  map[string][]string{},
		files:   map[string]string{},
		setting: defaultSetting,
		resp:    &http.Response{},
		copyBody: func() io.ReadCloser {
			return nil
		},
	}
}

// Get returns *RungoHTTPRequest with GET method.
func Get(url string) *RungoHTTPRequest {
	return NewrungoRequest(url, "GET")
}

// Post returns *RungoHTTPRequest with POST method.
func Post(url string) *RungoHTTPRequest {
	return NewrungoRequest(url, "POST")
}

// Put returns *RungoHTTPRequest with PUT method.
func Put(url string) *RungoHTTPRequest {
	return NewrungoRequest(url, "PUT")
}

// Delete returns *RungoHTTPRequest DELETE method.
func Delete(url string) *RungoHTTPRequest {
	return NewrungoRequest(url, "DELETE")
}

// Head returns *RungoHTTPRequest with HEAD method.
func Head(url string) *RungoHTTPRequest {
	return NewrungoRequest(url, "HEAD")
}

// RungoHTTPRequest provides more useful methods than http.Request for requesting an url.
type RungoHTTPRequest struct {
	url     string
	req     *http.Request
	params  map[string][]string
	files   map[string]string
	setting rungoHTTPSettings
	resp    *http.Response
	// body the response body, not the request body
	body []byte
	// copyBody support retry strategy to avoid copy request body
	copyBody func() io.ReadCloser
}

// GetRequest returns the request object
func (b *RungoHTTPRequest) GetRequest() *http.Request {
	return b.req
}

// Setting changes request settings
func (b *RungoHTTPRequest) Setting(setting rungoHTTPSettings) *RungoHTTPRequest {
	b.setting = setting
	return b
}

// SetBasicAuth sets the request's Authorization header to use HTTP Basic Authentication with the provided username and password.
func (b *RungoHTTPRequest) SetBasicAuth(username, password string) *RungoHTTPRequest {
	b.req.SetBasicAuth(username, password)
	return b
}

// SetEnableCookie sets enable/disable cookiejar
func (b *RungoHTTPRequest) SetEnableCookie(enable bool) *RungoHTTPRequest {
	b.setting.EnableCookie = enable
	return b
}

// SetUserAgent sets User-Agent header field
func (b *RungoHTTPRequest) SetUserAgent(useragent string) *RungoHTTPRequest {
	b.setting.UserAgent = useragent
	return b
}

// Retries sets Retries times.
// default is 0 (never retry)
// -1 retry indefinitely (forever)
// Other numbers specify the exact retry amount
func (b *RungoHTTPRequest) Retries(times int) *RungoHTTPRequest {
	b.setting.Retries = times
	return b
}

// RetryDelay sets the time to sleep between reconnection attempts
func (b *RungoHTTPRequest) RetryDelay(delay time.Duration) *RungoHTTPRequest {
	b.setting.RetryDelay = delay
	return b
}

// SetTimeout sets connect time out and read-write time out for rungoRequest.
func (b *RungoHTTPRequest) SetTimeout(connectTimeout, readWriteTimeout time.Duration) *RungoHTTPRequest {
	b.setting.ConnectTimeout = connectTimeout
	b.setting.ReadWriteTimeout = readWriteTimeout
	return b
}

// SetTLSClientConfig sets TLS connection configuration if visiting HTTPS url.
func (b *RungoHTTPRequest) SetTLSClientConfig(config *tls.Config) *RungoHTTPRequest {
	b.setting.TLSClientConfig = config
	return b
}

// Header adds header item string in request.
func (b *RungoHTTPRequest) Header(key, value string) *RungoHTTPRequest {
	b.req.Header.Set(key, value)
	return b
}

// SetHost set the request host
func (b *RungoHTTPRequest) SetHost(host string) *RungoHTTPRequest {
	b.req.Host = host
	return b
}

// SetProtocolVersion sets the protocol version for incoming requests.
// Client requests always use HTTP/1.1
func (b *RungoHTTPRequest) SetProtocolVersion(vers string) *RungoHTTPRequest {
	if vers == "" {
		vers = "HTTP/1.1"
	}

	major, minor, ok := http.ParseHTTPVersion(vers)
	if ok {
		b.req.Proto = vers
		b.req.ProtoMajor = major
		b.req.ProtoMinor = minor
		return b
	}
	logs.Error("%+v", berror.Errorf(InvalidUrlProtocolVersion, "invalid protocol: %s", vers))
	return b
}

// SetCookie adds a cookie to the request.
func (b *RungoHTTPRequest) SetCookie(cookie *http.Cookie) *RungoHTTPRequest {
	b.req.Header.Add("Cookie", cookie.String())
	return b
}

// SetTransport sets the transport field
func (b *RungoHTTPRequest) SetTransport(transport http.RoundTripper) *RungoHTTPRequest {
	b.setting.Transport = transport
	return b
}

// SetProxy sets the HTTP proxy
// example:
//
//	func(req *http.Request) (*url.URL, error) {
//		u, _ := url.ParseRequestURI("http://127.0.0.1:8118")
//		return u, nil
//	}
func (b *RungoHTTPRequest) SetProxy(proxy func(*http.Request) (*url.URL, error)) *RungoHTTPRequest {
	b.setting.Proxy = proxy
	return b
}

// SetCheckRedirect specifies the policy for handling redirects.
//
// If CheckRedirect is nil, the Client uses its default policy,
// which is to stop after 10 consecutive requests.
func (b *RungoHTTPRequest) SetCheckRedirect(redirect func(req *http.Request, via []*http.Request) error) *RungoHTTPRequest {
	b.setting.CheckRedirect = redirect
	return b
}

// SetFilters will use the filter as the invocation filters
func (b *RungoHTTPRequest) SetFilters(fcs ...FilterChain) *RungoHTTPRequest {
	b.setting.FilterChains = fcs
	return b
}

// AddFilters adds filter
func (b *RungoHTTPRequest) AddFilters(fcs ...FilterChain) *RungoHTTPRequest {
	b.setting.FilterChains = append(b.setting.FilterChains, fcs...)
	return b
}

// SetEscapeHTML is used to set the flag whether escape HTML special characters during processing
func (b *RungoHTTPRequest) SetEscapeHTML(isEscape bool) *RungoHTTPRequest {
	b.setting.EscapeHTML = isEscape
	return b
}

// Param adds query param in to request.
// params build query string as ?key1=value1&key2=value2...
func (b *RungoHTTPRequest) Param(key, value string) *RungoHTTPRequest {
	if param, ok := b.params[key]; ok {
		b.params[key] = append(param, value)
	} else {
		b.params[key] = []string{value}
	}
	return b
}

// PostFile adds a post file to the request
func (b *RungoHTTPRequest) PostFile(formname, filename string) *RungoHTTPRequest {
	b.files[formname] = filename
	return b
}

// Body adds request raw body.
// Supports string and []byte.
// TODO return error if data is invalid
func (b *RungoHTTPRequest) Body(data interface{}) *RungoHTTPRequest {
	switch t := data.(type) {
	case string:
		b.reqBody([]byte(t))
	case []byte:
		b.reqBody(t)
	default:
		logs.Error("%+v", berror.Errorf(UnsupportedBodyType, "unsupported body data type: %s", t))
	}
	return b
}

func (b *RungoHTTPRequest) reqBody(data []byte) *RungoHTTPRequest {
	body := io.NopCloser(bytes.NewReader(data))
	b.req.Body = body
	b.req.GetBody = func() (io.ReadCloser, error) {
		return body, nil
	}
	b.req.ContentLength = int64(len(data))
	b.copyBody = func() io.ReadCloser {
		return io.NopCloser(bytes.NewReader(data))
	}
	return b
}

// XMLBody adds the request raw body encoded in XML.
func (b *RungoHTTPRequest) XMLBody(obj interface{}) (*RungoHTTPRequest, error) {
	if b.req.Body == nil && obj != nil {
		byts, err := xml.Marshal(obj)
		if err != nil {
			return b, berror.Wrap(err, InvalidXMLBody, "obj could not be converted to XML data")
		}
		b.reqBody(byts)
		b.req.Header.Set(contentTypeKey, "application/xml")
	}
	return b, nil
}

// YAMLBody adds the request raw body encoded in YAML.
func (b *RungoHTTPRequest) YAMLBody(obj interface{}) (*RungoHTTPRequest, error) {
	if b.req.Body == nil && obj != nil {
		byts, err := yaml.Marshal(obj)
		if err != nil {
			return b, berror.Wrap(err, InvalidYAMLBody, "obj could not be converted to YAML data")
		}
		b.reqBody(byts)
		b.req.Header.Set(contentTypeKey, "application/x+yaml")
	}
	return b, nil
}

// JSONBody adds the request raw body encoded in JSON.
func (b *RungoHTTPRequest) JSONBody(obj interface{}) (*RungoHTTPRequest, error) {
	if b.req.Body == nil && obj != nil {
		byts, err := b.JSONMarshal(obj)
		if err != nil {
			return b, berror.Wrap(err, InvalidJSONBody, "obj could not be converted to JSON body")
		}
		b.reqBody(byts)
		b.req.Header.Set(contentTypeKey, "application/json")
	}
	return b, nil
}

func (b *RungoHTTPRequest) JSONMarshal(obj interface{}) ([]byte, error) {
	bf := bytes.NewBuffer([]byte{})
	jsonEncoder := json.NewEncoder(bf)
	jsonEncoder.SetEscapeHTML(b.setting.EscapeHTML)
	err := jsonEncoder.Encode(obj)
	if err != nil {
		return nil, err
	}
	return bf.Bytes(), nil
}

func (b *RungoHTTPRequest) buildURL(paramBody string) {
	// build GET url with query string
	if b.req.Method == "GET" && len(paramBody) > 0 {
		if strings.Contains(b.url, "?") {
			b.url += "&" + paramBody
		} else {
			b.url = b.url + "?" + paramBody
		}
		return
	}

	// build POST/PUT/PATCH url and body
	if (b.req.Method == "POST" || b.req.Method == "PUT" || b.req.Method == "PATCH" || b.req.Method == "DELETE") && b.req.Body == nil {
		// with files
		if len(b.files) > 0 {
			b.handleFiles()
			return
		}

		// with params
		if len(paramBody) > 0 {
			b.Header(contentTypeKey, "application/x-www-form-urlencoded")
			b.Body(paramBody)
		}
	}
}

func (b *RungoHTTPRequest) handleFiles() {
	pr, pw := io.Pipe()
	bodyWriter := multipart.NewWriter(pw)
	go func() {
		for formname, filename := range b.files {
			b.handleFileToBody(bodyWriter, formname, filename)
		}
		for k, v := range b.params {
			for _, vv := range v {
				_ = bodyWriter.WriteField(k, vv)
			}
		}
		_ = bodyWriter.Close()
		_ = pw.Close()
	}()
	b.Header(contentTypeKey, bodyWriter.FormDataContentType())
	b.req.Body = io.NopCloser(pr)
	b.Header("Transfer-Encoding", "chunked")
}

func (*RungoHTTPRequest) handleFileToBody(bodyWriter *multipart.Writer, formname string, filename string) {
	fileWriter, err := bodyWriter.CreateFormFile(formname, filename)
	const errFmt = "Httplib: %+v"
	if err != nil {
		logs.Error(errFmt, berror.Wrapf(err, CreateFormFileFailed,
			"could not create form file, formname: %s, filename: %s", formname, filename))
	}
	fh, err := os.Open(filename)
	if err != nil {
		logs.Error(errFmt, berror.Wrapf(err, ReadFileFailed, "could not open this file %s", filename))
	}
	// iocopy
	_, err = io.Copy(fileWriter, fh)
	if err != nil {
		logs.Error(errFmt, berror.Wrapf(err, CopyFileFailed, "could not copy this file %s", filename))
	}
	err = fh.Close()
	if err != nil {
		logs.Error(errFmt, berror.Wrapf(err, CloseFileFailed, "could not close this file %s", filename))
	}
}

func (b *RungoHTTPRequest) getResponse() (*http.Response, error) {
	if b.resp.StatusCode != 0 {
		return b.resp, nil
	}
	resp, err := b.DoRequest()
	if err != nil {
		return nil, err
	}
	b.resp = resp
	return resp, nil
}

// DoRequest executes client.Do
func (b *RungoHTTPRequest) DoRequest() (resp *http.Response, err error) {
	root := doRequestFilter
	if len(b.setting.FilterChains) > 0 {
		for i := len(b.setting.FilterChains) - 1; i >= 0; i-- {
			root = b.setting.FilterChains[i](root)
		}
	}
	return root(b.req.Context(), b)
}

// Deprecated: please use NewrungoRequestWithContext
func (b *RungoHTTPRequest) DoRequestWithCtx(ctx context.Context) (resp *http.Response, err error) {
	root := doRequestFilter
	if len(b.setting.FilterChains) > 0 {
		for i := len(b.setting.FilterChains) - 1; i >= 0; i-- {
			root = b.setting.FilterChains[i](root)
		}
	}
	return root(ctx, b)
}

func (b *RungoHTTPRequest) doRequest(_ context.Context) (*http.Response, error) {
	paramBody := b.buildParamBody()

	b.buildURL(paramBody)
	urlParsed, err := url.Parse(b.url)
	if err != nil {
		return nil, berror.Wrapf(err, InvalidUrl, "parse url failed, the url is %s", b.url)
	}

	b.req.URL = urlParsed

	trans := b.buildTrans()

	jar := b.buildCookieJar()

	client := &http.Client{
		Transport: trans,
		Jar:       jar,
	}

	if b.setting.UserAgent != "" && b.req.Header.Get("User-Agent") == "" {
		b.req.Header.Set("User-Agent", b.setting.UserAgent)
	}

	if b.setting.CheckRedirect != nil {
		client.CheckRedirect = b.setting.CheckRedirect
	}

	return b.sendRequest(client)
}

func (b *RungoHTTPRequest) sendRequest(client *http.Client) (resp *http.Response, err error) {
	// retries default value is 0, it will run once.
	// retries equal to -1, it will run forever until success
	// retries is set, it will retry fixed times.
	// Sleeps for a 400ms between calls to reduce spam
	for i := 0; b.setting.Retries == -1 || i <= b.setting.Retries; i++ {
		resp, err = client.Do(b.req)
		if err == nil {
			return
		}
		time.Sleep(b.setting.RetryDelay)
		b.req.Body = b.copyBody()
	}
	return nil, berror.Wrap(err, SendRequestFailed, "sending request fail")
}

func (b *RungoHTTPRequest) buildCookieJar() http.CookieJar {
	var jar http.CookieJar
	if b.setting.EnableCookie {
		if defaultCookieJar == nil {
			createDefaultCookie()
		}
		jar = defaultCookieJar
	}
	return jar
}

func (b *RungoHTTPRequest) buildTrans() http.RoundTripper {
	trans := b.setting.Transport

	if trans == nil {
		// create default transport
		trans = &http.Transport{
			TLSClientConfig:     b.setting.TLSClientConfig,
			Proxy:               b.setting.Proxy,
			DialContext:         TimeoutDialerCtx(b.setting.ConnectTimeout, b.setting.ReadWriteTimeout),
			MaxIdleConnsPerHost: 100,
		}
	} else if t, ok := trans.(*http.Transport); ok {
		// if b.transport is *http.Transport then set the settings.
		if t.TLSClientConfig == nil {
			t.TLSClientConfig = b.setting.TLSClientConfig
		}
		if t.Proxy == nil {
			t.Proxy = b.setting.Proxy
		}
		if t.DialContext == nil {
			t.DialContext = TimeoutDialerCtx(b.setting.ConnectTimeout, b.setting.ReadWriteTimeout)
		}
	}
	return trans
}

func (b *RungoHTTPRequest) buildParamBody() string {
	var paramBody string
	if len(b.params) > 0 {
		var buf bytes.Buffer
		for k, v := range b.params {
			for _, vv := range v {
				buf.WriteString(url.QueryEscape(k))
				buf.WriteByte('=')
				buf.WriteString(url.QueryEscape(vv))
				buf.WriteByte('&')
			}
		}
		paramBody = buf.String()
		paramBody = paramBody[0 : len(paramBody)-1]
	}
	return paramBody
}

// String returns the body string in response.
// Calls Response inner.
func (b *RungoHTTPRequest) String() (string, error) {
	data, err := b.Bytes()
	if err != nil {
		return "", err
	}

	return string(data), nil
}

// Bytes returns the body []byte in response.
// Calls Response inner.
func (b *RungoHTTPRequest) Bytes() ([]byte, error) {
	if b.body != nil {
		return b.body, nil
	}
	resp, err := b.getResponse()
	if err != nil {
		return nil, err
	}
	if resp.Body == nil {
		return nil, nil
	}
	defer resp.Body.Close()
	if b.setting.Gzip && resp.Header.Get("Content-Encoding") == "gzip" {
		reader, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, berror.Wrap(err, ReadGzipBodyFailed, "building gzip reader failed")
		}
		b.body, err = io.ReadAll(reader)
		return b.body, berror.Wrap(err, ReadGzipBodyFailed, "reading gzip data failed")
	}
	b.body, err = io.ReadAll(resp.Body)
	return b.body, err
}

// ToFile saves the body data in response to one file.
// Calls Response inner.
func (b *RungoHTTPRequest) ToFile(filename string) error {
	resp, err := b.getResponse()
	if err != nil {
		return err
	}
	if resp.Body == nil {
		return nil
	}
	defer resp.Body.Close()
	err = pathExistAndMkdir(filename)
	if err != nil {
		return err
	}
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)
	return err
}

// Check if the file directory exists. If it doesn't then it's created
func pathExistAndMkdir(filename string) (err error) {
	filename = filepath.Dir(filename)
	_, err = os.Stat(filename)
	if err == nil {
		return nil
	}
	if os.IsNotExist(err) {
		err = os.MkdirAll(filename, os.ModePerm)
		if err == nil {
			return nil
		}
	}
	return berror.Wrapf(err, CreateFileIfNotExistFailed, "try to create(if not exist) failed: %s", filename)
}

// ToJSON returns the map that marshals from the body bytes as json in response.
// Calls Response inner.
func (b *RungoHTTPRequest) ToJSON(v interface{}) error {
	data, err := b.Bytes()
	if err != nil {
		return err
	}
	return berror.Wrap(json.Unmarshal(data, v),
		UnmarshalJSONResponseToObjectFailed, "unmarshal json body to object failed.")
}

// ToXML returns the map that marshals from the body bytes as xml in response .
// Calls Response inner.
func (b *RungoHTTPRequest) ToXML(v interface{}) error {
	data, err := b.Bytes()
	if err != nil {
		return err
	}
	return berror.Wrap(xml.Unmarshal(data, v),
		UnmarshalXMLResponseToObjectFailed, "unmarshal xml body to object failed.")
}

// ToYAML returns the map that marshals from the body bytes as yaml in response .
// Calls Response inner.
func (b *RungoHTTPRequest) ToYAML(v interface{}) error {
	data, err := b.Bytes()
	if err != nil {
		return err
	}
	return berror.Wrap(yaml.Unmarshal(data, v),
		UnmarshalYAMLResponseToObjectFailed, "unmarshal yaml body to object failed.")
}

// ToValue attempts to resolve the response body to value using an existing method.
// Calls Response inner.
// If response header contain Content-Type, func will call ToJSON\ToXML\ToYAML.
// Else it will try to parse body as json\yaml\xml, If all attempts fail, an error will be returned
func (b *RungoHTTPRequest) ToValue(value interface{}) error {
	if value == nil {
		return nil
	}

	contentType := strings.Split(b.resp.Header.Get(contentTypeKey), ";")[0]
	// try to parse it as content type
	switch contentType {
	case "application/json":
		return b.ToJSON(value)
	case "text/xml", "application/xml":
		return b.ToXML(value)
	case "text/yaml", "application/x-yaml", "application/x+yaml":
		return b.ToYAML(value)
	}

	// try to parse it anyway
	if err := b.ToJSON(value); err == nil {
		return nil
	}
	if err := b.ToYAML(value); err == nil {
		return nil
	}
	if err := b.ToXML(value); err == nil {
		return nil
	}

	return berror.Error(UnmarshalResponseToObjectFailed, "unmarshal body to object failed.")
}

// Response executes request client gets response manually.
func (b *RungoHTTPRequest) Response() (*http.Response, error) {
	return b.getResponse()
}

// TimeoutDialer returns functions of connection dialer with timeout settings for http.Transport Dial field.
// Deprecated
// we will move this at the end of 2021
// please use TimeoutDialerCtx
func TimeoutDialer(cTimeout time.Duration, rwTimeout time.Duration) func(net, addr string) (c net.Conn, err error) {
	return func(netw, addr string) (net.Conn, error) {
		return TimeoutDialerCtx(cTimeout, rwTimeout)(context.Background(), netw, addr)
	}
}

func TimeoutDialerCtx(cTimeout time.Duration,
	rwTimeout time.Duration) func(ctx context.Context, net, addr string) (c net.Conn, err error) {
	return func(ctx context.Context, netw, addr string) (net.Conn, error) {
		conn, err := net.DialTimeout(netw, addr, cTimeout)
		if err != nil {
			return nil, err
		}
		err = conn.SetDeadline(time.Now().Add(rwTimeout))
		return conn, err
	}
}
