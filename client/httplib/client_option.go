// Copyright 2020 rungo
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package httplib

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"time"
)

type (
	ClientOption           func(client *Client)
	RungoHTTPRequestOption func(request *RungoHTTPRequest)
)

// WithEnableCookie will enable cookie in all subsequent request
func WithEnableCookie(enable bool) ClientOption {
	return func(client *Client) {
		client.Setting.EnableCookie = enable
	}
}

// WithUserAgent will adds UA in all subsequent request
func WithUserAgent(userAgent string) ClientOption {
	return func(client *Client) {
		client.Setting.UserAgent = userAgent
	}
}

// WithTLSClientConfig will adds tls config in all subsequent request
func WithTLSClientConfig(config *tls.Config) ClientOption {
	return func(client *Client) {
		client.Setting.TLSClientConfig = config
	}
}

// WithTransport will set transport field in all subsequent request
func WithTransport(transport http.RoundTripper) ClientOption {
	return func(client *Client) {
		client.Setting.Transport = transport
	}
}

// WithProxy will set http proxy field in all subsequent request
func WithProxy(proxy func(*http.Request) (*url.URL, error)) ClientOption {
	return func(client *Client) {
		client.Setting.Proxy = proxy
	}
}

// WithCheckRedirect will specifies the policy for handling redirects in all subsequent request
func WithCheckRedirect(redirect func(req *http.Request, via []*http.Request) error) ClientOption {
	return func(client *Client) {
		client.Setting.CheckRedirect = redirect
	}
}

// WithHTTPSetting can replace rungoHTTPSeting
func WithHTTPSetting(setting rungoHTTPSettings) ClientOption {
	return func(client *Client) {
		client.Setting = setting
	}
}

// WithEnableGzip will enable gzip in all subsequent request
func WithEnableGzip(enable bool) ClientOption {
	return func(client *Client) {
		client.Setting.Gzip = enable
	}
}

// RungoHTTPRequestOption

// WithTimeout sets connect time out and read-write time out for rungoRequest.
func WithTimeout(connectTimeout, readWriteTimeout time.Duration) RungoHTTPRequestOption {
	return func(request *RungoHTTPRequest) {
		request.SetTimeout(connectTimeout, readWriteTimeout)
	}
}

// WithHeader adds header item string in request.
func WithHeader(key, value string) RungoHTTPRequestOption {
	return func(request *RungoHTTPRequest) {
		request.Header(key, value)
	}
}

// WithCookie adds a cookie to the request.
func WithCookie(cookie *http.Cookie) RungoHTTPRequestOption {
	return func(request *RungoHTTPRequest) {
		request.Header("Cookie", cookie.String())
	}
}

// WithTokenFactory adds a custom function to set Authorization
func WithTokenFactory(tokenFactory func() string) RungoHTTPRequestOption {
	return func(request *RungoHTTPRequest) {
		t := tokenFactory()

		request.Header("Authorization", t)
	}
}

// WithBasicAuth adds a custom function to set basic auth
func WithBasicAuth(basicAuth func() (string, string)) RungoHTTPRequestOption {
	return func(request *RungoHTTPRequest) {
		username, password := basicAuth()
		request.SetBasicAuth(username, password)
	}
}

// WithFilters will use the filter as the invocation filters
func WithFilters(fcs ...FilterChain) RungoHTTPRequestOption {
	return func(request *RungoHTTPRequest) {
		request.SetFilters(fcs...)
	}
}

// WithContentType adds ContentType in header
func WithContentType(contentType string) RungoHTTPRequestOption {
	return func(request *RungoHTTPRequest) {
		request.Header(contentTypeKey, contentType)
	}
}

// WithParam adds query param in to request.
func WithParam(key, value string) RungoHTTPRequestOption {
	return func(request *RungoHTTPRequest) {
		request.Param(key, value)
	}
}

// WithRetry set retry times and delay for the request
// default is 0 (never retry)
// -1 retry indefinitely (forever)
// Other numbers specify the exact retry amount
func WithRetry(times int, delay time.Duration) RungoHTTPRequestOption {
	return func(request *RungoHTTPRequest) {
		request.Retries(times)
		request.RetryDelay(delay)
	}
}
