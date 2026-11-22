package core

import "testing"

func TestIsGoogleHKHost(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{host: "google.com.hk", want: true},
		{host: "www.google.com.hk", want: true},
		{host: "WWW.GOOGLE.COM.HK", want: true},
		{host: "www.google.com", want: false},
		{host: "www.google.co.jp", want: false},
		{host: "consent.google.com", want: false},
		{host: "evilgoogle.com.hk", want: false},
	}

	for _, tc := range cases {
		if got := isGoogleHKHost(tc.host); got != tc.want {
			t.Errorf("isGoogleHKHost(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}
