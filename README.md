# egressinator
Trying to get out of a network? But have no idea what ports are allowed?
This might help. 

Egressinator was heavily inspired by https://github.com/trustedsec/egressbuster, but is now written in golang, as the other project has fallen into disrepair. 
The server and client come as one package deal. 


A note, the server will not work on windows as it relies on iptables to redirect traffic.

# TLDR
```
git clone https://github.com/NHAS/egressinator.git
cd egressbuster
go build
```

# Help
```
Egressinator
Determine unrestricted ports that can egress the network
Usage of client:
  -address string
        Address of egressbuster server
  -range string
        Range of TCP ports to check, e.g 1-1024 (default "1-1024")
  -threads int
        Number of threads (default 500)
  -timeout int
        Time before a connection is seen as invalid (in seconds) (default 3)
  -verbose
        Display more output
Usage of server:
  -interface string
        interface for server listener
  -port int
        The port the egress detector server will listen on (default 4344)
  -src string
        Source address for server to listen for client requests
```
