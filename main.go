// sss is a simple secret sharing mechanism. It is a
// blatant ripoff of github/skx/sss rewritten in Go.
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

var rex = regexp.MustCompile(`^([a-zA-Z0-9/_-]+)$`)

type identifier interface {
	identify(*http.Request) (string, error)
}

type ipIdentifier int

func (_ ipIdentifier) identify(r *http.Request) (string, error) {
	return strings.Split(r.RemoteAddr, ":")[0], nil
}

func mkSecretsHandler(dir string, ider identifier) http.HandlerFunc {
	var err error
	dir, err = filepath.Abs(dir)
	if err != nil {
		panic(err)
	}

	h := func(w http.ResponseWriter, req *http.Request) {
		req.Body.Close()
		errString := func(code int, s string) {
			w.WriteHeader(code)
			w.Header().Add("Content-Type", "text/plain")
			fmt.Fprint(w, s)
		}

		if !rex.MatchString(req.URL.Path) {
			log.Println("Bad request", req.RemoteAddr, req.URL)
			errString(http.StatusBadRequest, "We only permit alphanumeric requests (along with '_' and  '-').")
			return
		}

		id, err := ider.identify(req)
		if err != nil {
			errString(http.StatusNotFound, "not found")
			log.Println("no id found: ", id, err)
			return
		}

		fn := filepath.Join(dir, filepath.Clean(filepath.Join(id, req.URL.Path+".json")))
		if !strings.HasPrefix(fn, dir) {
			log.Println("path traversal", req.RemoteAddr, id, fn)
			errString(http.StatusBadRequest, "path traversal")
			return
		}

		f, err := os.Open(fn)
		if err != nil {
			errString(http.StatusNotFound, "not found")
			log.Println("403/404 err: ", req.RemoteAddr, id, req.URL.Path, err)
			return
		}
		defer f.Close()

		w.WriteHeader(http.StatusOK)
		w.Header().Add("Content-Type", "application/json")
		_, err = io.Copy(w, f)
		if err != nil {
			log.Println("io err :", req.RemoteAddr, id, fn, err)
		}
		log.Println("OK!", req.RemoteAddr, id, fn)

	}
	return h

}

var usage = func() {
	fmt.Fprintf(os.Stderr, "Usage of %s:\n", path.Base(os.Args[0]))
	flag.PrintDefaults()
	o := `Serves a set of secrets to known clients.
Clients are identified by the connecting IP address.
`
	fmt.Fprint(os.Stderr, o)

}

func main() {
	var (
		port = flag.String("port", "1337", "Port to listen to")
		dir  = flag.String("dir", "./secrets", "Secrets store")
		cert = flag.String("cert", "", "Certificate public key")
		key  = flag.String("key", "", "Certificate private key")
	)
	flag.Usage = usage

	flag.Parse()

	http.HandleFunc("/", mkSecretsHandler(*dir, ipIdentifier(0)))
	server := &http.Server{Handler: http.DefaultServeMux}
	var err error

	if *cert != "" && *key != "" {
		server.Addr = fmt.Sprintf(":%s", *port)
		log.Printf("Listening on %s", server.Addr)
		err = server.ListenAndServeTLS(*cert, *key)
	} else {
		server.Addr = fmt.Sprintf("localhost:%s", *port)
		log.Printf("Not running on through TLS - listening on %s", server.Addr)
		err = server.ListenAndServe()
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Err: %s\nExiting\n", err)
		os.Exit(1)
	}
}
