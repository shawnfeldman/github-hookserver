package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	log "github.com/sirupsen/logrus"
)

var port *int

func init() {
	port = flag.Int("port", 8000, "add port to serve")
	log.SetFormatter(&log.JSONFormatter{PrettyPrint: true})
	log.SetOutput(os.Stdout)
	log.SetLevel(log.InfoLevel)
}

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		l := log.WithFields(log.Fields{
			"request_uri": r.RequestURI,
			"method":      r.Method,
			"path":        r.URL.Path,
		})
		if r.Body != nil {
			b, err := ioutil.ReadAll(r.Body)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				l.WithError(err).Warn("failed to read body")
				return
			}
			var m map[string]interface{}
			err = json.Unmarshal(b, &m)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte("couldn't parse body."))
				l.WithError(err).WithField("body", string(b)).Warn("failed to parse body")
				return
			}
			l.WithField("body", m).Info("parsed body")
		}
		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte("Accepted."))
	})

	fs := http.FileServer(http.Dir("static/"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	http.ListenAndServe(fmt.Sprintf(":%d", *port), nil)
}
