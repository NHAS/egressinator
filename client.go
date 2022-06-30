package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

func ClientSubCommand() *clientCommand {
	gc := &clientCommand{
		fs: flag.NewFlagSet("client", flag.ContinueOnError),
	}

	gc.fs.IntVar(&gc.timeout, "timeout", 3, "Time before a connection is seen as invalid (in seconds)")
	gc.fs.IntVar(&gc.maxThreads, "threads", 500, "Number of threads")
	gc.fs.BoolVar(&gc.verbose, "verbose", false, "Display more output")
	gc.fs.StringVar(&gc.portRange, "range", "1-1024", "Range of TCP ports to check, e.g 1-1024")

	gc.fs.StringVar(&gc.address, "address", "", "Address of egressbuster server")

	return gc
}

type clientCommand struct {
	fs *flag.FlagSet

	timeout    int
	maxThreads int
	verbose    bool
	portRange  string
	address    string

	lowPort  int
	highPort int
}

func (g *clientCommand) PrintUsage() {
	g.fs.Usage()
}

func (g *clientCommand) Name() string {
	return g.fs.Name()
}

func (g *clientCommand) Init(args []string) error {
	err := g.fs.Parse(args)
	if err != nil {
		return err
	}

	portRange := strings.Split(g.portRange, "-")
	if len(portRange) != 2 {
		log.Fatal("Invalid port range specified, should be in the format of 1-65536")
	}

	g.lowPort, err = strconv.Atoi(portRange[0])
	if err != nil {
		log.Fatal("Could not parse low port: ", err)
	}

	g.highPort, err = strconv.Atoi(portRange[1])
	if err != nil {
		log.Fatal("Could not parse high port: ", err)
	}

	if g.lowPort > g.highPort {
		log.Fatal("Lowport is bigger than high port, invalid")
	}

	if g.highPort > 65536 {
		log.Println("Highport is greater than max number of ports, limiting to TCP 65536")
		g.highPort = 65536
	}

	_, _, err = net.ParseCIDR(g.address)
	if err != nil {
		if net.ParseIP(g.address) == nil {
			log.Fatal("Could not parse Ip address or range from: ", g.address)
		}
	}

	return nil
}

func (g *clientCommand) Run() error {
	limit := make(chan bool, g.maxThreads)

	log.Printf("[i] Sending packets to egress listener (%s)...\n", g.address)
	log.Printf("[i] Starting at: %d/tcp, ending at: %d/tcp\n", g.lowPort, g.highPort)

	var wg sync.WaitGroup
	for currentPort := g.lowPort; currentPort <= g.highPort; currentPort++ {
		limit <- true
		wg.Add(1)
		go func(currentPort int) {
			defer func() {
				<-limit
				wg.Done()
			}()

			if g.verbose || currentPort%1000 == 0 {
				log.Println("[i] Trying: TCP ", currentPort)
			}

			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", g.address, currentPort), time.Duration(g.timeout)*time.Second)
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

			log.Printf("[*] Connection made to %s on port: %d/tcp\n", g.address, currentPort)

		}(currentPort)
	}

	wg.Wait()

	log.Println("Finished!")
	return nil
}
