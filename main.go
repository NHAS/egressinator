package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"time"
)

var (
	timeout    = flag.Int("timeout", 3, "Time before a connection is seen as invalid (in seconds)")
	maxThreads = flag.Int("threads", 500, "Number of threads")
	verbose    = flag.Bool("verbose", false, "Display more output")
	ports      = flag.String("range", "1-1024", "Range of TCP ports to check, e.g 1-1024")

	address    = flag.String("address", "", "Address of egressbuster server")
	intr       = flag.String("interface", "", "interface for server listener")
	srcAddress = flag.String("src_address", "", "Source address for server to listen for client requests")
	serverPort = flag.Int("server_port", 4344, "The port the egress detector server will listen on")

	server = flag.Bool("server", false, "Become a server")

	lowPort  int
	highPort int
)

func main() {

	flag.Parse()

	flag.Visit(func(f *flag.Flag) {
		if f.Name == "server" {
			*server = true
		}
	})

	portRange := strings.Split(*ports, "-")
	if len(portRange) != 2 {
		log.Fatal("Invalid port range specified, should be in the format of 1-65536")
	}

	var err error

	lowPort, err = strconv.Atoi(portRange[0])
	if err != nil {
		log.Fatal("Could not parse low port: ", err)
	}

	highPort, err = strconv.Atoi(portRange[1])
	if err != nil {
		log.Fatal("Could not parse high port: ", err)
	}

	if lowPort > highPort {
		log.Fatal("Lowport is bigger than high port, invalid")
	}

	if highPort > 65536 {
		log.Println("Highport is greater than max number of ports, limiting to TCP 65536")
		highPort = 65536
	}

	if net.ParseIP(*address) == nil {
		log.Fatal("Could not parse address from: ", *address)
	}

	if *server {
		ifaces, err := net.Interfaces()
		if err != nil {
			log.Fatal("Unable to get list of interfaces: ", err)
		}

		found := false
		for _, iface := range ifaces {
			if iface.Name == *intr {

				if *address == "" {
					addrs, err := iface.Addrs()
					if err != nil {
						log.Fatal("No local address for the server was identified")
					}

					if len(addrs) == 0 {
						log.Fatal("No local address for the server was identified")
					}

					*address = addrs[0].String()
				}

				found = true
				break
			}
		}

		if !found {
			log.Fatalf("Could not find interface by name of '%s', are you sure that is correct?\n", *intr)
		}

		Server()
		return
	}

	Client()
}

func Server() {

	if _, err := exec.LookPath("iptables"); err != nil {
		log.Fatal("Unable to find iptables in your $PATH")
	}

	log.Printf("[*] Inserting iptables rule to redirect connections from %s to **all TCP ports** to Egress Buster port %d/tcp\n", *srcAddress, serverPort)
	err := exec.Command("iptables", "-t", "nat", "-I", "PREROUTING", "-s", *srcAddress, "-i",
		*intr, "-p", "tcp", "--dport", "1:65535", "-j", "DNAT",
		"--to-destination", fmt.Sprintf("%s:%d", *address, serverPort)).Run()
	if err != nil {
		log.Fatal("Unable to set iptables to redirect all connection attempts to egress server: ", err)
	}

	defer func() {
		err := exec.Command("iptables", "-t", "nat", "-D", "PREROUTING", "-s", *srcAddress, "-i",
			*intr, "-p", "tcp", "--dport", "1:65535", "-j", "DNAT",
			"--to-destination", fmt.Sprintf("%s:%d", *address, serverPort)).Run()
		if err != nil {
			log.Fatal("Unable to delete iptables rules, you may have to do this yourself.", err)
		}

	}()

	c := make(chan os.Signal, 1)
	connections := make(chan net.Conn)

	signal.Notify(c, os.Interrupt)

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *serverPort))
	if err != nil {
		log.Println("Unable to start listener: ", err)
		return
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				continue
			}

			go func() {

				connections <- conn
			}()
		}
	}()

	buff := make([]byte, 256)

	for {
		select {
		case <-c:
			listener.Close()
			return
		case newConn := <-connections:
			log.Printf("[*] Got connection from %s!\n", newConn.RemoteAddr().String())

			n, err := newConn.Read(buff)
			if err != nil {
				continue
			}

			selfReportedPort := strings.Split(string(buff[:n]), ":")
			if len(selfReportedPort) == 0 {
				log.Println("\t[i] Potentially invalid, client didnt self report port")
				continue
			}

			if len(selfReportedPort) != 2 {
				log.Printf("\t[i] Potentially invalid, send data, but it wasnt in the correct format '%s'\n", string(buff[:n]))
				continue
			}

			if selfReportedPort[0] != "egressor" {
				log.Printf("\t[i] Potentially invalid, send data, but it wasnt in the correct format '%s'\n", string(buff[:n]))
				continue
			}

			log.Printf("[i] Client said '%s'/tcp was successful\n", selfReportedPort[1])

		}
	}

}

func Client() {

	limit := make(chan bool, *maxThreads)

	log.Printf("[i] Sending packets to egress listener (%s)...\n", *address)
	log.Printf("[i] Starting at: %d/tcp, ending at: %d/tcp\n", lowPort, highPort)

	for currentPort := lowPort; currentPort <= highPort; currentPort++ {
		limit <- true
		go func(currentPort int) {
			defer func() {
				<-limit
			}()

			if *verbose || currentPort%1000 == 0 {
				log.Println("[i] Trying: TCP ", currentPort)
			}

			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", *address, currentPort), time.Duration(*timeout)*time.Second)
			if err != nil {
				return
			}
			defer conn.Close()

			msg := fmt.Sprintf("egressor:%d", currentPort)
			_, err = conn.Write([]byte(msg))
			if err != nil {
				log.Printf("[+] Initial connection worked on port %d/tcp however sending message failed, %s\n", currentPort, err.Error())
				return
			}

			log.Printf("[*] Connection made to %s on port: %d/tcp\n", *address, currentPort)

		}(currentPort)
	}

	log.Println("Finished!")
}
