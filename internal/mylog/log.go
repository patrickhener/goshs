package mylog

import (
	"log"
)

//LogRequest will log the request in a uniform way
func LogRequest(remoteAddr, method, url, proto, status string) {
	if status == "500" || status == "404" {
		log.Printf("ERROR: %s - - \"%s %s %s\" - %+v", remoteAddr, method, url, proto, status)
		return
	}
	log.Printf("INFO:  %s - - \"%s %s %s\" - %+v", remoteAddr, method, url, proto, status)
}

//LogMessage will log an arbitrary message to the console
func LogMessage(message string) {
	log.Println(message)
}
