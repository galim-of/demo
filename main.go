package main

import (
	"demo/dbl"
	"demo/web"
	"log"
	"net/http"
)

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Llongfile)
	http.HandleFunc("/auth", web.Authenticate)
	http.HandleFunc("/register", web.Register)
	http.HandleFunc("/refresh", web.Refresh)
	http.HandleFunc("/delete", web.Delete)
	http.HandleFunc("/deleteAll", web.DeleteAll)
	http.ListenAndServe(":8080", nil)

	defer func() {
		if err := dbl.Close(); err != nil {
			log.Println("Can't close database", err)
		}
	}()
}
