package mikrotik

import (
	"bytes"
	"io"
	"log"
	"net"
	"net/http"
)

func GetIPAddress() string {
	resp, err := http.Get("https://icanhazip.com")
	if err != nil {
		return ""
	}
	text, _ := io.ReadAll(resp.Body)
	return string(text)
}

func WaitOnline(host string) {
	for {
		addrs, err := net.LookupHost(host)
		if err != nil {
			log.Printf("internet connection offline, resolving %s fails with: %v\n", host, addrs)
		} else if len(addrs) > 0 {
			log.Printf("internet connection online, %s resolves to: %v\n", host, addrs)
			return
		}
	}
}

func ResetRouterInterface(interface_url, user, pass string) error {
	// do stuff

	req, _ := http.NewRequest("PATCH", interface_url, bytes.NewBufferString(`{"disabled": "true"}`))
	req.SetBasicAuth(user, pass)
	_, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	req, _ = http.NewRequest("PATCH", interface_url, bytes.NewBufferString(`{"disabled": "false"}`))
	req.SetBasicAuth(user, pass)
	_, err = http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	return nil
}
