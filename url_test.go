package urlhash

import "testing"

func TestHash(t *testing.T) {
	testCases := []struct {
		url          string
		expected     string
		allowedWords map[string]struct{}
		salt         string
	}{
		{
			url:      "my.openshift.api.console.customer.com",
			expected: "05.98ee192d6.479.95d230c.ee8ca6dd.6f3",
		},
		{
			url:      "https://my.openshift.api.console.customer.com",
			expected: "https://05.98ee192d6.479.95d230c.ee8ca6dd.6f3",
		},
		{
			url:      "https://my.openshift.api.console.customer.com/path/to/something/openshift",
			expected: "https://05.98ee192d6.479.95d230c.ee8ca6dd.6f3/b5bf/39/ca74813cb/98ee192d6",
		},
		{
			url:      "http://my.openshift.api.console.customer.com",
			expected: "http://05.98ee192d6.479.95d230c.ee8ca6dd.6f3",
		},
		{
			url:      "tftp://my.openshift.api.console.customer.com",
			expected: "tftp://05.98ee192d6.479.95d230c.ee8ca6dd.6f3",
		},
		{
			url:      "https://my.openshift.api.console.customer.com",
			expected: "https://5a.758be91d3.c4c.840c123.d6474651.b02",
			salt:     "mysalt",
		},
		{
			url:      "https://my.openshift.api.console.customer.com",
			expected: "https://c0.34432a95c.101.cffa6a3.7f29f533.f45",
			salt:     "mysalt1",
		},
		{
			url:          "https://my.openshift.api.console.customer.com",
			expected:     "https://05.openshift.api.console.ee8ca6dd.com",
			allowedWords: OpenShiftWords,
		},
		{
			url:          "http://my.openshift.api.console.customer.com",
			expected:     "http://5a.openshift.api.console.d6474651.com",
			allowedWords: OpenShiftWords,
			salt:         "mysalt",
		},
		{
			url:          "https://my.openshift-console-ingress.api.console.customer.com",
			expected:     "https://05.openshift-console-5bd922e.api.console.ee8ca6dd.com",
			allowedWords: OpenShiftWords,
		},
		{
			url:          "https://my.openshift-console-ingress.api.console.customer.com/path/to/something/openshift",
			expected:     "https://05.openshift-console-5bd922e.api.console.ee8ca6dd.com/b5bf/39/ca74813cb/openshift",
			allowedWords: OpenShiftWords,
		},
		{
			url:      "127.0.0.1",
			expected: "04c.7e9.7e9.b4b",
		},
		{
			url:      "127.0.0.1",
			expected: "a1f.6a3.6a3.024",
			salt:     "mysalt",
		},
		{
			url:      "https://127.0.0.1",
			expected: "https://04c.7e9.7e9.b4b",
		},
		{
			url:      "127.0.0.2",
			expected: "04c.7e9.7e9.b35",
		},
		{
			url:      "127.0.0.1/path/to/something/openshift",
			expected: "04c.7e9.7e9.b4b/b5bf/39/ca74813cb/98ee192d6",
		},
		{
			url:      "127.0.0.0/24",
			expected: "04c.7e9.7e9.7e9/db",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.url, func(t *testing.T) {
			SetAllowedWords(tc.allowedWords)
			out := HashURL(tc.url, tc.salt)
			if out != tc.expected {
				t.Errorf("Got %s expected %s", out, tc.expected)
			}
		})
	}
}
