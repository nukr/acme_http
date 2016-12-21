package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"golang.org/x/crypto/acme"

	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB
var domain string

func init() {
	db, err := sql.Open("sqlite3", "./foo.db")
	if err != nil {
		log.Fatal(err)
	}
	sqlStmt := `
  create table if not exists foo (id integer not null primary key, name text);
  delete from foo;
  `
	_, err = db.Exec(sqlStmt)
	if err != nil {
		log.Printf("%q: %s\n", err, sqlStmt)
		return
	}
	flag.StringVar(&domain, "d", "", "domain you want issue")
	flag.Parse()
}

func main() {
	defer db.Close()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	client := &acme.Client{Key: key, DirectoryURL: "https://acme-staging.api.letsencrypt.org/directory"}
	ctx := context.Background()
	_, err = client.Register(ctx, nil, acme.AcceptTOS)
	if err != nil {
		log.Fatal(err)
	}
	authz, err := client.Authorize(ctx, domain)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(authz.URI)
	var chal *acme.Challenge
	for _, c := range authz.Challenges {
		if c.Type == "http-01" {
			chal = c
			break
		}
	}
	fmt.Println(chal.URI)
	path := client.HTTP01ChallengePath(chal.Token)
	fmt.Println(path)
	resp, err := client.HTTP01ChallengeResponse(chal.Token)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(resp)

	go func(p, res string) {
		http.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "%s", res)
		})
		http.ListenAndServe(":8087", nil)
	}(path, resp)

	time.Sleep(time.Minute)

	_, err = client.Accept(ctx, chal)
	if err != nil {
		log.Fatal(err)
	}
	_, err = client.WaitAuthorization(ctx, authz.URI)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("done")
}
