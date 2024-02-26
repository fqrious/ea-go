package main

import (
	"ea-bot/mikrotik"
	"log"
)

func main() {
	// ea.Start()
	for i := 0; i < 5; i++ {
		log.Println("ip address:", mikrotik.GetIPAddress())
		mikrotik.WaitOnline("www.google.com")
		log.Println("ip address:", mikrotik.GetIPAddress())
		mikrotik.ResetRouterInterface("http://192.168.88.1/rest/interface/lte1", "admin", "Peugeot607")
	}
}
