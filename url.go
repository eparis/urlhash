package urlhash

import (
	"crypto/sha256"
	"fmt"
	"net"
	"net/url"
	"strconv"
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
	out := ""
	slashParts := strings.Split(str, "/")
	for i, slashPart := range slashParts {
		if i == 0 {
			// This looks like an IP, so make the hash len==3 instead of
			// equal to len(word)
			if net.ParseIP(slashPart) != nil {
				out = out + hashIP(slashPart, salt)
				// if this is a CIDR do a horrid hack to detect and print
				if len(slashParts) == 2 {
					val, err := strconv.Atoi(slashParts[1])
					if err != nil || val < 0 || val > 255 {
						continue
					}
					return out + "/" + slashParts[1]
				}
				continue
			}
		} else {
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
	out := ""
	u, err := url.Parse(urlString)
	if err != nil {
		return hash(urlString, salt)
	}
	if u.Scheme != "" {
		out = u.Scheme + "://"
	}
	if u.Host != "" {
		out = out + hashString(u.Host, salt)
		if u.Path != "" {
			out = out + hashString(u.Path, salt)
		}
	} else if u.Path != "" {
		// If the host was not found, treat the path as the host
		out = out + hashString(u.Path, salt)
	}
	return out
}
