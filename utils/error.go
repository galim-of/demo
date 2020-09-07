package utils

import (
	"log"
)

//CloseApp will close app
func CloseApp(err error, msg ...string) {
	if len(msg) > 0 {
		if err != nil {
			log.Fatal(err, msg)
		}
	}
	if err != nil {
		log.Fatal(err)
	}
}

//PrintError prints error to stdout if err != nil
func PrintError(err error) {
	if err != nil {
		log.Println(err)
	}
}
