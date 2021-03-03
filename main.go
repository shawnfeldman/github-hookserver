package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"

	github "github.com/google/go-github/github"
	log "github.com/sirupsen/logrus"
)

var (
	port         *int
	secret       *string
	printBody    *bool
	printHeaders *bool
)

func init() {
	port = flag.Int("port", 8000, "add port to serve")
	secret = flag.String("secret", "", "add a secret")
	printBody = flag.Bool("body", false, "print body?")
	printHeaders = flag.Bool("headers", false, "print header?")

	log.SetFormatter(&log.JSONFormatter{PrettyPrint: true})
	log.SetOutput(os.Stdout)
	log.SetLevel(log.InfoLevel)
}

func main() {
	flag.Parse()
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		l := log.WithFields(log.Fields{
			"request_uri": r.RequestURI,
			"method":      r.Method,
			"path":        r.URL.Path,
		})

		if *printHeaders {
			l = l.WithField("headers", r.Header)
		}

		fmt.Println(fmt.Sprintf("mysecret %s", *secret))
		payload, err := github.ValidatePayload(r, []byte(*secret))
		if err != nil {
			l = l.WithField("validation_error", err)
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
