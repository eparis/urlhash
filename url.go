package urlhash

import (
	"crypto/sha256"
	"fmt"
	"net"
	"net/url"
	"strings"
)

var (
	allowedWords   = map[string]struct{}{}
	OpenShiftWords = map[string]struct{}{
		"kubernetes": {},
		"k8s":        {},
		"openshift":  {},
		"console":    {},
		"api":        {},
		"com":        {},
		"net":        {},
		"org":        {},
	}
)

// Returns the sha256 value of salt+value
func hash(value string, salt string) string {
	input := salt + value
	output := sha256.Sum256([]byte(input))
	return fmt.Sprintf("%x", output)
}

// Returns the last len(value) sha256 values of salt+value
func hashTrunc(value string, salt string) string {
	hashVal := hash(value, salt)
	hashLen := len(hashVal)
	partLen := len(value)
	if hashLen > partLen {
		hashVal = hashVal[hashLen-partLen:]
	}
	return hashVal
}

// Returns the len(word) hash of a 'word'.
// returns the word itself if it is 'allowed'
func hashWord(word, salt string) string {
	if _, ok := allowedWords[word]; ok {
		return word
	}
	return hashTrunc(word, salt)
}

// Returns the hash of salt+IP.
// always returns 3 bytes for each component of the IP.
func hashIP(ip string, salt string) string {
	out := ""
	parts := strings.Split(ip, ".")
	for i, part := range parts {
		if i != 0 {
			out = out + "."
		}
		hashVal := hash(part, salt)
		hashVal = hashVal[len(hashVal)-3:]
		out = fmt.Sprintf("%s%s", out, hashVal)
	}
	return out
}

// Break the string on `/`, `.`, and `-`. Individually salt+hash each of those
// `words`. If all of the 'stuff' before the `/` looks like an IP handle it a little
// differently.
func hashString(str, salt string) string {
	if ip := net.ParseIP(str); ip != nil {
		return hashIP(str, salt)
	}
	out := ""
	slashParts := strings.Split(str, "/")
	for i, slashPart := range slashParts {
		if i != 0 {
			out = out + "/"
		}
		dotParts := strings.Split(slashPart, ".")
		for j, dotPart := range dotParts {
			if j != 0 {
				out = out + "."
			}
			dashParts := strings.Split(dotPart, "-")
			for k, word := range dashParts {
				if k != 0 {
					out = out + "-"
				}
				out = out + hashWord(word, salt)
			}
		}
	}
	return out
}

func validCIDR(in string) bool {
	_, _, err := net.ParseCIDR(in)
	if err != nil {
		return false
	}
	return true
}

func cidrHash(cidr, salt string) string {
	parts := strings.Split(cidr, "/")
	// do hash the IP portion
	out := hashIP(parts[0], salt)
	out = out + "/"
	// do not hash the subnet len
	out = out + parts[1]
	return out
}

// SetAllowedWords allows you to specify words which will not be hashed. These will
// instead be returned unchanged.
func SetAllowedWords(allowed map[string]struct{}) {
	allowedWords = allowed
}

// HashURL takes an url and returns a hash. This hash should be non-trivial to get the
// original value, but should be stable. So one can compare the output of the hash accross
// different urls. For example if openshift and com are in the 'AllowedWords' the urls
// might hash as:
//    https://this.openshift.com -> https://0a31.openshift.com
//    https://that.openshift.com -> https://deb4.openshift.com
//    https://this.that -> https://0a31.deb4
func HashURL(urlString, salt string) string {
	// If it looks like a cidr (aka 192.168.0.0/24) parse it.
	if validCIDR(urlString) {
		return cidrHash(urlString, salt)
	}

	// Make sure that every string parses with a 'Scheme'. Stoopid RFC. Without this we
	// parse things like `127.0.0.1:8080` very oddly.
	if !strings.Contains(urlString, "://") {
		urlString = "placeholder://" + urlString
	}

	// Parse it
	u, err := url.Parse(urlString)
	if err != nil {
		// If we still don't look like a URL, just hash it and move along
		return hash(urlString, salt)
	}

	// Just print the scheme (except if it is our magic string
	out := ""
	if u.Scheme != "" && u.Scheme != "placeholder" {
		out = u.Scheme + "://"
	}

	// has the hostname
	host := u.Hostname()
	if host != "" {
		out = out + hashString(host, salt)
	}

	// hash the port
	port := u.Port()
	if port != "" {
		out = out + ":" + hashString(port, salt)
	}

	// hash the path
	path := u.Path
	if path != "" {
		// If the host was not found, treat the path as the host
		out = out + hashString(path, salt)
	}
	return out
}
