package main

import (
    "fmt"
    "github.com/laurent/argparse"
    "io/ioutil"
    "net/http"
    "log"
    "os"
)

func identity(w http.ResponseWriter, r *http.Request, url string) {
    resp, err := http.Get(url + "/identity/tutu")
    if err != nil {
	    log.Fatal("http get", err)
    }
    defer resp.Body.Close()
    bodyBytes, err2 := ioutil.ReadAll(resp.Body)
    if err2 != nil {
	    log.Fatal("ioutil", err2)
    }
    fmt.Fprintf(w, string(bodyBytes))
}

func main() {
    parser := argparse.NewParser("wrapper", "")
    var url *string = parser.String("u", "url", &argparse.Options{Required: true, Help: ""})
    err := parser.Parse(os.Args)
    if err != nil {
        fmt.Print(parser.Usage(err))
    }
    log.Printf(*url)
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        identity(w, r, *url)
    })
    err2 := http.ListenAndServe(":8080", nil)
    if err2 != nil {
        log.Fatal("ListenAndServe: ", err2)
    }
}

