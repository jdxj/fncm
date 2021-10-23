package main

import (
	"log"
)

func main() {
	err := Execute()
	if err != nil {
		log.Println(err)
	}
}
