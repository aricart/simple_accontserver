package main

import (
	"flag"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/aricart/nst.go"
	"github.com/nats-io/jwt/v2"
	nslogger "github.com/nats-io/nats-server/v2/logger"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

func main() {
	var dir string
	var creds string
	var err error
	var sysConn *nats.Conn

	flag.StringVar(&dir, "dir", "./", "directory for assets and JWTs")
	flag.StringVar(&creds, "sys-creds", "./sys.creds", "credentials file for the system user")
	flag.Parse()

	logger := nslogger.NewStdLogger(true, true, true, true, true)
	logger.Noticef("assets dir %q", dir)

	sysConn, err = nats.Connect("nats://localhost:4222", nats.UserCredentials(creds))
	if err != nil {
		logger.Fatalf("error connecting to nats: %v", err)
	}

	mux := http.NewServeMux()

	getOperator := func(w http.ResponseWriter, r *http.Request) {
		d, err := os.ReadFile(filepath.Join(dir, "operator.jwt"))
		if err != nil {
			logger.Noticef("error processing %v", err)
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(d)
		}
	}

	// account server protocol is just some URLs
	// these need to return the operator
	mux.HandleFunc("GET /jwt/v1/operator", getOperator)
	mux.HandleFunc("GET /jwt/v2/operator", getOperator)

	trimPath := func(p string) string {
		return strings.TrimSuffix(strings.TrimPrefix(p, "/"), "/")
	}

	getAccount := func(p string) string {
		p = trimPath(p)
		chunks := strings.Split(p, "/")
		if len(chunks) != 4 {
			return ""
		}
		return chunks[3]
	}

	// the url for getting accounts are also used as pings - the url is usually expected to
	// have the account public key
	mux.HandleFunc("GET /jwt/v2/accounts/", func(w http.ResponseWriter, r *http.Request) {
		account := getAccount(r.URL.Path)
		if account == "" {
			// ping
			w.WriteHeader(http.StatusOK)
			return
		}

		// just get them from the resolver
		token, err := nst.GetAccount(sysConn, account)
		if err != nil {
			logger.Errorf("error %v: %v", r.URL.Path, err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/jwt")
		_, _ = w.Write([]byte(token))
		logger.Noticef("get %v", account)
	})

	mux.HandleFunc("POST /jwt/v2/accounts/", func(w http.ResponseWriter, r *http.Request) {
		account := getAccount(r.URL.Path)
		if account == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		data, err := io.ReadAll(r.Body)
		if err != nil {
			logger.Noticef("error %v: %v", r.URL.Path, err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		ac, err := jwt.DecodeAccountClaims(string(data))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// account must be self-signed
		if ac.Issuer != ac.Subject {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		// the operator then needs to sign them after it checks it out
		d, err := os.ReadFile(filepath.Join(dir, "operator.nk"))
		if err != nil {
			logger.Errorf("error %v: %v", r.URL.Path, err)
			w.WriteHeader(http.StatusInternalServerError)
		}
		// load the operator key (should be a signing key)
		okp, err := nkeys.FromSeed(d)
		if err != nil {
			logger.Errorf("error %v: %v", r.URL.Path, err)
			w.WriteHeader(http.StatusInternalServerError)
		}
		// encode the account with the operator key
		token, err := ac.Encode(okp)
		if err != nil {
			logger.Errorf("error %v: %v", r.URL.Path, err)
			w.WriteHeader(http.StatusInternalServerError)
		}
		// push it to the nats resolver via the system account
		// nsc will read the account, and update itself with the operator account
		rr, err := nst.UpdateAccount(sysConn, token)
		if err != nil {
			logger.Errorf("error %v: %v", r.URL.Path, err)
			w.WriteHeader(http.StatusInternalServerError)
		}
		if rr.UpdateData.Code == 200 {
			w.WriteHeader(http.StatusOK)
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			// you can return any message here
			w.Write([]byte("UPDATED"))
			logger.Noticef("update %v: %s", account, rr.UpdateData.Message)
		} else {
			logger.Errorf("update %v: %s", account, rr.UpdateData.Message)
			w.WriteHeader(http.StatusInternalServerError)
		}
	})

	logger.Noticef("accepting requests on port 8080")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		panic(err)
	}

	runtime.Goexit()
}
