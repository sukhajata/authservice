package mocks

import (
	"net/http"
	"net/url"
)

// MockClient is the mock client
type MockHTTPClient struct {
	// Response can be set before invoking functions
	Response *http.Response

	// Error can be set before invoking functions
	Error error
}

// Do is the mock client's `Do` func
func (m *MockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return m.Response, m.Error
}

// PostForm mocks a form post
func (m *MockHTTPClient) PostForm(url string, data url.Values) (*http.Response, error) {
	return m.Response, m.Error
}
