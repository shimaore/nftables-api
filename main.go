/*
nftables-api - add an ip to local nftables blocklists

The MIT License (MIT)

Copyright (c) 2025 Fred Posner

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

Example build commands:
GOOS=linux GOARCH=amd64 go build -o nftables-api
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o nftables-api
GOOS=linux GOARCH=arm GOARM=7 go build -o nftables-api-pi

*/

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"

	"github.com/apiban/nftlib"
	"github.com/tidwall/sjson"
)

var (
	apiPort     string
	setName     string
	logFile     string
	logFileLine bool
	logLicense  bool
	useipv6     bool
)

func init() {
	flag.StringVar(&apiPort, "port", "8084", "port to listen on")
	flag.StringVar(&apiPort, "p", "8084", "port to listen on")

	flag.StringVar(&logFile, "log", "/var/log/nftables-api.log", "location of log file or - for stdout")
	flag.StringVar(&logFile, "l", "/var/log/nftables-api.log", "location of log file or - for stdout")

	flag.StringVar(&setName, "setname", "APIBANLOCAL", "set name for entries")
	flag.StringVar(&setName, "s", "APIBANLOCAL", "set name for entries")

	flag.BoolVar(&logFileLine, "logextra", false, "add filename to log")
	flag.BoolVar(&logFileLine, "x", false, "add filename to log")

	flag.BoolVar(&logLicense, "license", false, "print license in log")
	flag.BoolVar(&logLicense, "c", false, "print license in log")

	flag.BoolVar(&useipv6, "ipv6", true, "use ipv6 (default is true)")
	flag.BoolVar(&useipv6, "i", true, "use ipv6 (default is true)")
}

func main() {
	// get flags
	flag.Parse()

	// Open our Log
	if logFile != "-" && logFile != "stdout" {
		lf, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			log.Panic(err)
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			runtime.Goexit()
		}

		defer lf.Close()
		if logFileLine {
			log.SetFlags(log.Lshortfile | log.LstdFlags)
		} else {
			log.SetFlags(log.LstdFlags)
		}

		log.SetOutput(lf)
	}

	InitLog()
	router := http.NewServeMux()
	router.HandleFunc("GET /add/{ipaddress}", addIPAddress)
	router.HandleFunc("GET /addip/{ipaddress}", addIPAddress)
	router.HandleFunc("GET /block/{ipaddress}", addIPAddress)
	router.HandleFunc("GET /blockip/{ipaddress}", addIPAddress)
	router.HandleFunc("GET /flush", flushSet)
	router.HandleFunc("GET /flushset", flushSet)
	router.HandleFunc("GET /remove/{ipaddress}", removeIPAddress)
	router.HandleFunc("GET /removeip/{ipaddress}", removeIPAddress)
	router.HandleFunc("GET /unblock/{ipaddress}", removeIPAddress)
	router.HandleFunc("GET /unblockip/{ipaddress}", removeIPAddress)
	// coming later, long day
	//router.HandleFunc("DELETE /", deleteHandle)
	//router.HandleFunc("POST /", postHandle)
	//router.HandleFunc("PUT /", putHandle)
	log.Print("[+] starting http server")
	http.ListenAndServe("0.0.0.0:"+apiPort, router)
}

func addIPAddress(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	ipaddress := r.PathValue("ipaddress")
	log.Println("[o] received addIPAddress request", ipaddress)

	ipType, err := checkIPAddressv4(ipaddress)
	if err != nil {
		log.Println("[x]", ipaddress, "is not a valid ip address")
		JSONHandleError(w, r, "aIP01", err.Error(), 400)
		return
	}

	setDetails, err := NftCheckSet(setName)
	if err != nil {
		log.Println("[x] check set error:", err.Error())
		JSONHandleError(w, r, "aIP02", err.Error(), 500)
		return

	}

	if ipType == "ipv6" && !useipv6 {
		log.Println("[x] cannot use ipv6")
		JSONHandleError(w, r, "aIP03", "unable to use ipv6 address", 403)
		return
	}

	if ipType == "ipv6" {
		setDetails, err = nftlib.NftListSet(setName + "v6")
		if err != nil {
			log.Println("[x] cannot find ipv6 chain", err.Error())
			JSONHandleError(w, r, "aIP04", err.Error(), 500)
			return
		}
	}

	err = nftlib.NftAddSetElement(setDetails, ipaddress)
	if err != nil {
		log.Println("[x] adding set element failed", err.Error())
		JSONHandleError(w, r, "aIP05", err.Error(), 500)
		return
	}

	log.Println("[+] added / blocked:", ipaddress)
	jsonresp, _ := sjson.Set("", "status", "ok")
	jsonresp, _ = sjson.Set(jsonresp, "ipaddress", ipaddress)
	jsonresp, _ = sjson.Set(jsonresp, "details", "added to set "+setDetails.Set)
	io.WriteString(w, jsonresp+"\n")
}

func checkIPAddress(ip string) bool {
	if net.ParseIP(ip) == nil {
		return false
	} else {
		return true
	}
}

func checkIPAddressv4(ip string) (string, error) {
	if net.ParseIP(ip) == nil {
		return "err", errors.New("Not an IP address")
	}

	for i := 0; i < len(ip); i++ {
		switch ip[i] {
		case '.':
			return "ipv4", nil
		case ':':
			return "ipv6", nil
		}
	}

	return "err", errors.New("unknown error")
}

func flushSet(w http.ResponseWriter, r *http.Request) {
	log.Println("[o] flush request received")
	setDetails, err := NftCheckSet(setName)
	if err != nil {
		log.Println("[x] set check failed:", err.Error())
		JSONHandleError(w, r, "fS00", err.Error(), 500)
		return
	}

	err = nftlib.NftFlushSet(setDetails)
	if err != nil {
		log.Println("[x] flush set", setDetails.Set, "failed:", err.Error())
		JSONHandleError(w, r, "fS01", err.Error(), 500)
		return
	}

	if useipv6 {
		setDetails, err = nftlib.NftListSet(setName + "v6")
		if err != nil {
			log.Println("[x] cannot find ipv6 chain", err.Error())
			JSONHandleError(w, r, "fS02", err.Error(), 500)
			return
		}

		err = nftlib.NftFlushSet(setDetails)
		if err != nil {
			log.Println("[x] flush set", setDetails.Set, "failed:", err.Error())
			JSONHandleError(w, r, "fS03", err.Error(), 500)
			return
		}
	}

	log.Println("[+] flushed")
	jsonresp, _ := sjson.Set("", "status", "ok")
	jsonresp, _ = sjson.Set(jsonresp, "details", "flushed set(s)")
	io.WriteString(w, jsonresp+"\n")
}

func InitLog() {
	log.Print("-> [o] Starting nftables-api")
	if logLicense {
		log.Print(" --- ")
		log.Print("The MIT License (MIT)")
		log.Print(" ")
		log.Print("Copyright (c) 2025 Fred Posner")
		log.Print(" ")
		log.Print("Permission is hereby granted, free of charge, to any person obtaining a copy")
		log.Print("of this software and associated documentation files (the \"Software\"), to deal")
		log.Print("in the Software without restriction, including without limitation the rights")
		log.Print("to use, copy, modify, merge, publish, distribute, sublicense, and/or sell")
		log.Print("copies of the Software, and to permit persons to whom the Software is")
		log.Print("furnished to do so, subject to the following conditions:")
		log.Print(" ")
		log.Print("The above copyright notice and this permission notice shall be included in all")
		log.Print("copies or substantial portions of the Software.")
		log.Print(" ")
		log.Print("THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR")
		log.Print("IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,")
		log.Print("FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE")
		log.Print("AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER")
		log.Print("LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,")
		log.Print("OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE")
		log.Print("SOFTWARE.")
		log.Print(" --- ")
	} else {
		log.Print("** Copyright (C) 2025 Fred Posner / The Palner Group, Inc.")
		log.Print("** This program comes with ABSOLUTELY NO WARRANTY;")
		log.Print("** This is free software, and you are welcome to redistribute it under certain conditions")
		log.Print("** See LICENSE (on github or via -c --license flag) for details.")
	}

	log.Println("-> [.] Listening on port:", apiPort)
	log.Println("-> [.] Log extra", logFileLine)
	log.Println("-> [.] nftables set", setName)
}

func JSONHandleError(w http.ResponseWriter, r *http.Request, errCode string, errDesc string, httpCode int64) {
	log.Println("[JSONHandleError]", httpCode, errCode, errDesc)
	w.Header().Set("Content-Type", "application/json")
	httpJson, _ := sjson.Set("", "status", httpCode)
	httpJson, _ = sjson.Set(httpJson, "error", errCode)
	httpJson, _ = sjson.Set(httpJson, "details", errDesc)
	switch httpCode {
	case 400:
		w.WriteHeader(http.StatusBadRequest)
	case 403:
		w.WriteHeader(http.StatusForbidden)
	case 404:
		w.WriteHeader(http.StatusNotFound)
	case 408:
		w.WriteHeader(http.StatusRequestTimeout)
	case 429:
		w.WriteHeader(http.StatusTooManyRequests)
	case 500:
		w.WriteHeader(http.StatusInternalServerError)
	case 503:
		w.WriteHeader(http.StatusServiceUnavailable)
	default:
		w.WriteHeader(http.StatusBadRequest)
	}

	io.WriteString(w, httpJson+"\n")
}

func NftAddSet(setname string) error {
	log.Println("** Attempting to add set and rules")
	log.Println("[-] finding input chains")
	inputChains, err := nftlib.NftGetInputChains()
	if err != nil {
		log.Println("[x] error finding input chain:", err.Error())
		return errors.New("error finding an input chain")
	}

	log.Println("[.] found", inputChains)
	chainDetails, err := nftlib.NftGetChainDetails(inputChains[0])
	if err != nil {
		log.Println("[x] error finding input chain details:", err.Error())
		return errors.New("error getting input chain details")
	}

	log.Println("[.] creating set", setname, "in", chainDetails.Table, chainDetails.Chain)
	err = nftlib.NftAddSet(chainDetails, setname)
	if err != nil {
		log.Println("[x] unable to create set:", err.Error())
		return errors.New("unable to create set")
	}

	log.Println("[.] creating input rule", setname, "in", chainDetails.Table, chainDetails.Chain)
	err = nftlib.NftAddSetRuleInput(chainDetails, setname)
	if err != nil {
		log.Println("[*] unable to create input rule:", err.Error())
		log.Println("[*] input rule failed. Set created though... continuing.")
		log.Println("[*] *** PLEASE MANUALLY CREATE A RULE FOR THE", setname, "SET")
	}

	log.Println("[-] finding output chains")
	outputchains, err := nftlib.NftGetOutputChains()
	if err != nil {
		log.Println("[x] error finding output chain:", err.Error())
		return nil
	}

	log.Println("[.] found", outputchains)
	chainDetails, err = nftlib.NftGetChainDetails(outputchains[0])
	if err != nil {
		log.Println("[x] error finding output chain details:", err.Error())
		return nil
	}

	log.Println("[.] creating output rule", setname, "in", chainDetails.Table, chainDetails.Chain)
	err = nftlib.NftAddSetRuleOutput(chainDetails, setname)
	if err != nil {
		log.Println("[*] unable to create output rule:", err.Error())
		log.Println("[*] output rule failed. Set created though... continuing.")
		log.Println("[*] *** PLEASE MANUALLY CREATE A RULE FOR THE", setname, "SET")
	}

	return nil
}

func NftAddv6Set(setname string) error {
	log.Println("** Attempting to add ipv6 set and rules")
	log.Println("[-] finding input chains")
	inputChains, err := nftlib.NftGetInputChains()
	if err != nil {
		log.Println("[x] error finding input chain:", err.Error())
		return errors.New("error finding an input chain")
	}

	log.Println("[.] found", inputChains)
	chainDetails, err := nftlib.NftGetChainDetails(inputChains[0])
	if err != nil {
		log.Println("[x] error finding input chain details:", err.Error())
		return errors.New("error getting input chain details")
	}

	if chainDetails.Family != "inet" {
		log.Println("[x] error:", chainDetails.Family, "does not support ipv6.")
		useipv6 = false
		return errors.New("chain does not support ipv6")
	}

	log.Println("[.] creating set", setname, "in", chainDetails.Table, chainDetails.Chain)
	err = nftlib.NftAddv6Set(chainDetails, setname)
	if err != nil {
		log.Println("[x] unable to create set:", err.Error())
		useipv6 = false
		return errors.New("unable to create set")
	}

	log.Println("[.] creating input rule", setname, "in", chainDetails.Table, chainDetails.Chain)
	err = nftlib.NftAddSetRulev6Input(chainDetails, setname)
	if err != nil {
		log.Println("[*] unable to create input rule:", err.Error())
		log.Println("[*] input rule failed. Set created though... continuing.")
		log.Println("[*] *** PLEASE MANUALLY CREATE A RULE FOR THE", setname, "SET")
	}

	log.Println("[-] finding output chains")
	outputchains, err := nftlib.NftGetOutputChains()
	if err != nil {
		log.Println("[x] error finding output chain:", err.Error())
		return nil
	}

	log.Println("[.] found", outputchains)
	chainDetails, err = nftlib.NftGetChainDetails(outputchains[0])
	if err != nil {
		log.Println("[x] error finding output chain details:", err.Error())
		return nil
	}

	log.Println("[.] creating output rule", setname, "in", chainDetails.Table, chainDetails.Chain)
	err = nftlib.NftAddSetRulev6Output(chainDetails, setname)
	if err != nil {
		log.Println("[*] unable to create output rule:", err.Error())
		log.Println("[*] output rule failed. Set created though... continuing.")
		log.Println("[*] *** PLEASE MANUALLY CREATE A RULE FOR THE", setname, "SET")
	}

	return nil
}

func NftCheckSet(setname string) (nftlib.NFTABLES, error) {
	currentSet, err := nftlib.NftListSet(setname)
	if err != nil {
		log.Println("[x] Cannot verify nftables set:", setname)
		log.Println("[x] error:", err.Error())
		log.Println("[.] trying to create set")
		seterr := NftAddSet(setname)
		if seterr != nil {
			log.Println("[x] cannot create set", setname, ":", err.Error())
			return currentSet, errors.New("cannot create set")
		}

		currentSet, err = nftlib.NftListSet(setname)
		if err != nil {
			log.Println("[x]", err.Error())
			log.Println("[x] Still cannot verify nftables set:", setname)
			return currentSet, errors.New("cannot verify set exists")
		}

		log.Println("[+]", currentSet.Set, "verified")
	}

	log.Println("[.]", setname, "exists. Currently has", len(currentSet.Elements), "elements.")

	if useipv6 {
		v6set := setname + "v6"
		_, err := nftlib.NftListSet(v6set)
		if err != nil {
			log.Println("[x] Cannot verify nftables set:", v6set)
			log.Println("[x] error:", err.Error())
			log.Println("[.] trying to create set")
			seterr := NftAddv6Set(v6set)
			if seterr != nil {
				log.Println("[x] cannot create set", v6set, ":", err.Error())
				useipv6 = false
			} else {
				_, err = nftlib.NftListSet(v6set)
				if err != nil {
					log.Println("[x]", err.Error())
					log.Println("[x] Still cannot verify nftables set:", v6set)
					useipv6 = false
				} else {
					log.Println("[+]", currentSet.Set, "verified")
				}
			}
		}
	}

	return currentSet, nil
}

func removeIPAddress(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	ipaddress := r.PathValue("ipaddress")
	log.Println("[o] received removeIPAddress request", ipaddress)

	ipType, err := checkIPAddressv4(ipaddress)
	if err != nil {
		log.Println("[x]", ipaddress, "is not a valid ip address")
		JSONHandleError(w, r, "rIP01", err.Error(), 400)
		return
	}

	setDetails, err := NftCheckSet(setName)
	if err != nil {
		log.Println("[x] check set error:", err.Error())
		JSONHandleError(w, r, "rIP02", err.Error(), 500)
		return

	}

	if ipType == "ipv6" && !useipv6 {
		log.Println("[x] cannot use ipv6")
		JSONHandleError(w, r, "rIP03", "unable to use ipv6 address", 403)
		return
	}

	if ipType == "ipv6" {
		setDetails, err = nftlib.NftListSet(setName + "v6")
		if err != nil {
			log.Println("[x] cannot find ipv6 chain", err.Error())
			JSONHandleError(w, r, "rIP04", err.Error(), 500)
			return
		}
	}

	err = nftlib.NftDelSetElement(setDetails, ipaddress)
	if err != nil {
		log.Println("[x] removing set element failed", err.Error())
		JSONHandleError(w, r, "rIP05", err.Error(), 500)
		return
	}

	log.Println("[+] removed / unblocked:", ipaddress)
	jsonresp, _ := sjson.Set("", "status", "ok")
	jsonresp, _ = sjson.Set(jsonresp, "ipaddress", ipaddress)
	jsonresp, _ = sjson.Set(jsonresp, "details", "removed from set "+setDetails.Set)
	io.WriteString(w, jsonresp+"\n")
}
