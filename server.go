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
	"time"
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

	gc.fs.StringVar(&gc.address, "address", "", "Manually set external/interface address")

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

	if g.address != "" {

		if net.ParseIP(g.address) == nil {
			return fmt.Errorf("Could not parse ipaddress from " + g.address)
		}

	} else {
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

					fmt.Println(addrs)

					g.address = getIp(addrs[0].String())
				}

				found = true
				break
			}
		}

		if !found {
			return fmt.Errorf("Could not find interface by name of '%s', are you sure that is correct?\n", g.iface)
		}
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

	ipv6 := net.ParseIP(g.address).To4() == nil
	iptablesExecutable := "iptables"
	if ipv6 {
		iptablesExecutable = "ip6tables"
	}

	if _, err := exec.LookPath(iptablesExecutable); err != nil {
		return fmt.Errorf("Unable to find " + iptablesExecutable + " in your $PATH")
	}

	log.Printf("[*] Inserting %s rule to redirect connections from %s to %s, egressinator port %d/tcp\n", iptablesExecutable, g.address, g.src, g.port)

	output, err := exec.Command(iptablesExecutable, "-t", "filter", "-I", "INPUT", "-s", g.src, "-i",
		g.iface, "-p", "tcp", "-m", "tcp", "--dport", fmt.Sprintf("%d", g.port), "-j", "ACCEPT").CombinedOutput()
	if err != nil {
		fmt.Println(string(output))
		return fmt.Errorf("Unable to add %s rule to allow input to port %d: %s", iptablesExecutable, g.port, err)
	}

	output, err = exec.Command(iptablesExecutable, "-t", "nat", "-I", "PREROUTING", "-s", g.src, "-i",
		g.iface, "-p", "tcp", "--dport", "1:65535", "-j", "DNAT",
		"--to-destination", fmt.Sprintf("%s:%d", g.address, g.port)).CombinedOutput()

	if err != nil {
		fmt.Println(string(output))
		return fmt.Errorf("Unable to set %s to redirect all connection attempts to egress server: %s", iptablesExecutable, err)
	}

	defer func() {

		output, err := exec.Command(iptablesExecutable, "-t", "filter", "-D", "INPUT", "-s", g.src, "-i",
			g.iface, "-p", "tcp", "-m", "tcp", "--dport", fmt.Sprintf("%d", g.port), "-j", "ACCEPT").CombinedOutput()
		if err != nil {
			fmt.Println(string(output))
			log.Fatalf("Unable to delete %s rule to allow input to port %d: %s", iptablesExecutable, g.port, err)
		}

		err = exec.Command(iptablesExecutable, "-t", "nat", "-D", "PREROUTING", "-s", g.src, "-i",
			g.iface, "-p", "tcp", "--dport", "1:65535", "-j", "DNAT",
			"--to-destination", fmt.Sprintf("%s:%d", g.address, g.port)).Run()
		if err != nil {
			log.Fatal("Unable to delete ", iptablesExecutable, " rules, you may have to do this yourself.", err)
		}

	}()

	c := make(chan os.Signal, 1)
	connections := make(chan net.Conn)

	signal.Notify(c, os.Interrupt)

	network := "tcp"
	if ipv6 {
		network = "tcp6"
	}
	listener, err := net.Listen(network, fmt.Sprintf("%s:%d", g.address, g.port))
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
			go func() {
				newConn.SetDeadline(time.Now().Add(1 * time.Second))

				log.Printf("[*] Got connection from %s\n", newConn.RemoteAddr().String())

				n, err := newConn.Read(buff)
				if err != nil {
					return
				}

				selfReportedPort := strings.Split(string(buff[:n]), ":")
				if len(selfReportedPort) == 0 {
					log.Println("\t[i] Potentially invalid, client didnt self report port")
					return
				}

				if len(selfReportedPort) != 2 {
					log.Printf("\t[i] Potentially invalid, send data, but it wasnt in the correct format '%s'\n", string(buff[:n]))
					return
				}

				if selfReportedPort[0] != "egressor" {
					log.Printf("\t[i] Potentially invalid, send data, but it wasnt in the correct format '%s'\n", string(buff[:n]))
					return
				}

				log.Printf("[i] Client said '%s'/tcp was successful\n", selfReportedPort[1])
			}()

		}
	}

}
