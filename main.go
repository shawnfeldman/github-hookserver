package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	github "github.com/google/go-github/github"
	log "github.com/sirupsen/logrus"
)

var (
	port         *int
	secret       *string
	printBody    *bool
	printHeaders *bool
	timeout      *bool
	validate     *bool
)

const (
	// sha1Prefix is the prefix used by GitHub before the HMAC hexdigest.
	sha1Prefix = "sha1"
	// sha256Prefix and sha512Prefix are provided for future compatibility.
	sha256Prefix = "sha256"
	sha512Prefix = "sha512"
	// signatureHeader is the GitHub header key used to pass the HMAC hexdigest.
	signatureHeader = "X-Hub-Signature"
)

func init() {
	port = flag.Int("port", 8000, "add port to serve")
	secret = flag.String("secret", "", "add a secret")
	validate = flag.Bool("validate", true, "validate the request")
	printBody = flag.Bool("body", false, "print body?")
	timeout = flag.Bool("timeout", false, "timeout?")
	printHeaders = flag.Bool("headers", false, "print header?")

	log.SetFormatter(&log.JSONFormatter{PrettyPrint: true})
	log.SetOutput(os.Stdout)
	log.SetLevel(log.InfoLevel)
}

func main() {
	flag.Parse()
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		var err error
		if *timeout {
			log.Infof("%s %s", r.Method, r.URL.Path)
			time.Sleep(time.Second * 240)
		}
		l := log.WithFields(log.Fields{
			"request_uri": r.RequestURI,
			"method":      r.Method,
			"path":        r.URL.Path,
		})

		if *printHeaders {
			l = l.WithField("headers", r.Header)
		}

		fmt.Printf("mysecret %s /n", *secret)
		var payload []byte
		if *validate {
			payload, err = github.ValidatePayload(r, []byte(*secret))
			if err != nil {
				l.WithError(err).Error("could validate body")
				return
			}
		} else {
			payload, err = ioutil.ReadAll(r.Body)
			if err != nil {
				l = l.WithField("body_error", err)
				l.WithError(err).Error("could ready body")
				return
			}
		}
		event, err := github.ParseWebHook(github.WebHookType(r), payload)
		if err != nil {
			l.WithError(err).Error("could not parse webhook")
			return
		}

		switch event.(type) {
		case *github.PushEvent:
			l = l.WithField("event_type", "push")
		case *github.PullRequestEvent:
			l = l.WithField("event_type", "pull")
		case *github.WatchEvent:
			l = l.WithField("event_type", "watch")
		default:
			l = l.WithField("event_type", "unknown")
		}

		if *printBody {
			l = l.WithField("body", event)
		}

		l.Info("done.")
		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte("Accepted."))
	})

	fs := http.FileServer(http.Dir("static/"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	http.ListenAndServe(fmt.Sprintf(":%d", *port), nil)
}

func ValidatePayload(r *http.Request, secretKey []byte) (payload []byte, err error) {
	var body []byte // Raw body that GitHub uses to calculate the signature.

	switch ct := r.Header.Get("Content-Type"); ct {
	case "application/json":
		var err error
		if body, err = ioutil.ReadAll(r.Body); err != nil {
			return nil, err
		}

		// If the content type is application/json,
		// the JSON payload is just the original body.
		payload = body

	case "application/x-www-form-urlencoded":
		// payloadFormParam is the name of the form parameter that the JSON payload
		// will be in if a webhook has its content type set to application/x-www-form-urlencoded.
		const payloadFormParam = "payload"

		var err error
		if body, err = ioutil.ReadAll(r.Body); err != nil {
			return nil, err
		}

		// If the content type is application/x-www-form-urlencoded,
		// the JSON payload will be under the "payload" form param.
		form, err := url.ParseQuery(string(body))
		if err != nil {
			return nil, err
		}
		payload = []byte(form.Get(payloadFormParam))

	default:
		return nil, fmt.Errorf("Webhook request has unsupported Content-Type %q", ct)
	}

	sig := r.Header.Get(signatureHeader)
	if err := validateSignature(sig, body, secretKey); err != nil {
		return nil, err
	}
	return payload, nil
}
func validateSignature(signature string, payload, secretKey []byte) error {
	messageMAC, hashFunc, err := messageMAC(signature)
	if err != nil {
		return err
	}
	if !checkMAC(payload, messageMAC, secretKey, hashFunc) {
		return errors.New("payload signature check failed")
	}
	return nil
}

// messageMAC returns the hex-decoded HMAC tag from the signature and its
// corresponding hash function.
func messageMAC(signature string) ([]byte, func() hash.Hash, error) {
	if signature == "" {
		return nil, nil, errors.New("missing signature")
	}
	sigParts := strings.SplitN(signature, "=", 2)
	if len(sigParts) != 2 {
		return nil, nil, fmt.Errorf("error parsing signature %q", signature)
	}

	var hashFunc func() hash.Hash
	switch sigParts[0] {
	case sha1Prefix:
		hashFunc = sha1.New
	case sha256Prefix:
		hashFunc = sha256.New
	case sha512Prefix:
		hashFunc = sha512.New
	default:
		return nil, nil, fmt.Errorf("unknown hash type prefix: %q", sigParts[0])
	}

	buf, err := hex.DecodeString(sigParts[1])
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding signature %q: %v", signature, err)
	}
	return buf, hashFunc, nil
}

// genMAC generates the HMAC signature for a message provided the secret key
// and hashFunc.
func genMAC(message, key []byte, hashFunc func() hash.Hash) []byte {
	mac := hmac.New(hashFunc, key)
	mac.Write(message)
	return mac.Sum(nil)
}

// checkMAC reports whether messageMAC is a valid HMAC tag for message.
func checkMAC(message, messageMAC, key []byte, hashFunc func() hash.Hash) bool {
	expectedMAC := genMAC(message, key, hashFunc)
	return hmac.Equal(messageMAC, expectedMAC)
}
