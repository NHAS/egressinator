//go:build !windows

package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
)

func init() {
	cmds = append(cmds, ServerSubCommand())
}

type serverCommand struct {
	fs *flag.FlagSet

	iface   string
	src     string
	port    int
	address string
}

func ServerSubCommand() *serverCommand {
	gc := &serverCommand{
		fs: flag.NewFlagSet("server", flag.ContinueOnError),
	}

	gc.fs.StringVar(&gc.iface, "interface", "", "interface for server listener")
	gc.fs.StringVar(&gc.src, "src", "", "Source address for server to listen for client requests")

	gc.fs.IntVar(&gc.port, "port", 4344, "The port the egress detector server will listen on")

	return gc
}

func (g *serverCommand) Name() string {

	return g.fs.Name()
}

func (g *serverCommand) PrintUsage() {

	g.fs.Usage()
}

func (g *serverCommand) Init(args []string) error {
	err := g.fs.Parse(args)
	if err != nil {
		return err
	}

	if g.iface == "" {
		return fmt.Errorf("No interface specified, please specify an interface")
	}

	if g.src == "" {
		log.Println("No src address specified, will use 0.0.0.0/0")
		g.src = "0.0.0.0/0"
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("Unable to get list of interfaces: %s", err)
	}

	found := false
	for _, iface := range ifaces {
		if iface.Name == g.iface {

			if g.address == "" {
				addrs, err := iface.Addrs()
				if err != nil {
					return fmt.Errorf("No local address for the server was identified")
				}

				if len(addrs) == 0 {
					return fmt.Errorf("No local address for the interface was identified")
				}

				g.address = getIp(addrs[0].String())
			}

			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("Could not find interface by name of '%s', are you sure that is correct?\n", g.iface)
	}

	return nil
}

func getIp(addr string) string {
	for i := len(addr) - 1; i > 0; i-- {
		if addr[i] == ':' || addr[i] == '/' {
			return addr[:i]
		}
	}
	return addr
}

func (g *serverCommand) Run() error {

	if syscall.Getuid() != 0 {
		return fmt.Errorf("The server is not running as the root user, it will not be able to run iptables")
	}

	if _, err := exec.LookPath("iptables"); err != nil {
		return fmt.Errorf("Unable to find iptables in your $PATH")
	}

	log.Printf("[*] Inserting iptables rule to redirect connections from %s to egressinator port %d/tcp\n", g.src, g.port)
	output, err := exec.Command("iptables", "-t", "nat", "-I", "PREROUTING", "-s", g.src, "-i",
		g.iface, "-p", "tcp", "--dport", "1:65535", "-j", "DNAT",
		"--to-destination", fmt.Sprintf("%s:%d", g.address, g.port)).CombinedOutput()
	if err != nil {
		fmt.Println(string(output))
		return fmt.Errorf("Unable to set iptables to redirect all connection attempts to egress server: %s", err)
	}

	defer func() {
		err := exec.Command("iptables", "-t", "nat", "-D", "PREROUTING", "-s", g.src, "-i",
			g.iface, "-p", "tcp", "--dport", "1:65535", "-j", "DNAT",
			"--to-destination", fmt.Sprintf("%s:%d", g.address, g.port)).Run()
		if err != nil {
			log.Fatal("Unable to delete iptables rules, you may have to do this yourself.", err)
		}

	}()

	c := make(chan os.Signal, 1)
	connections := make(chan net.Conn)

	signal.Notify(c, os.Interrupt)

	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", g.address, g.port))
	if err != nil {
		return fmt.Errorf("Unable to start listener: %s", err.Error())
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
			log.Println("Got ctrl c, shutting down and removing iptables rules...")
			listener.Close()
			return nil
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
