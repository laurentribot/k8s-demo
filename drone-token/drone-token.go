package main

import (
	"database/sql"
	"encoding/base32"
	"fmt"
	"log"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/securecookie"
	_ "github.com/mattn/go-sqlite3"
)

func main() {

	// generate the user hash
	hash := base32.StdEncoding.EncodeToString(
		securecookie.GenerateRandomKey(32),
	)

	db, err := sql.Open("sqlite3", "/var/lib/drone/drone.sqlite")
	if err != nil {
		log.Fatal(err)
	}

	// insert the user into the database
	_, err = db.Exec(stmt, hash, "laurent")
	if err != nil {
		log.Fatal(err)
	}

	// generate and sign the jwt token for the user
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims{
		StandardClaims: jwt.StandardClaims{},
		Type:           "user",
		Text:           "laurent",
	})
	secret, err := token.SignedString([]byte(hash))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%s", secret)
}

type claims struct {
	jwt.StandardClaims
	Type string `json:"type"`
	Text string `json:"text"`
}

const stmt = `
UPDATE users
SET user_hash = ?
WHERE user_login = ?
`