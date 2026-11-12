package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"strconv"

	libvapour "github.com/aoiflux/libvapour"
	"github.com/aoiflux/libvapour/examples/internal/cli"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/linux/socketlist"
	"github.com/aoiflux/libvapour/tools/windows/network"
)

func main() {
	var flags cli.Flags
	flags.Register(flag.CommandLine)
	all := flag.Bool("all", false, "linux only: list every socket family, not only IPv4 and IPv6")
	image := cli.Parse("network [flags] <image>")
	if err := run(os.Stdout, os.Stderr, image, flags, *all); err != nil {
		log.Fatal(err)
	}
}

func run(stdout, stderr io.Writer, image string, flags cli.Flags, all bool) error {
	session, err := libvapour.OpenMemory(image, flags.OS, flags.Config())
	if err != nil {
		return err
	}
	defer session.Close()
	defer func() { cli.PrintDiagnostics(stderr, session.Diagnostics(), flags.Verbose) }()
	ctx := session.Context()

	if !flags.Windows() {
		sockets, err := socketlist.Run(ctx)
		if err != nil {
			return fmt.Errorf("%s: %w", socketlist.Name, err)
		}
		cli.Heading(stdout, "sockets held open by processes ("+socketlist.Name+")")
		printSockets(stdout, sockets, all)
		return nil
	}

	// Each list stands alone: a build the table walk refuses still has
	// endpoints in pool memory, so one failure does not hide the other list.
	var failures []error
	for _, source := range []struct {
		title string
		run   func(tools.Context) ([]network.Endpoint, error)
	}{
		{"endpoints in tcpip.sys's tables (" + network.NetworkListName + ")", network.RunNetworkList},
		{"endpoint objects found by pool scan (" + network.Name + ")", network.Run},
	} {
		cli.Heading(stdout, source.title)
		endpoints, err := source.run(ctx)
		if err != nil {
			fmt.Fprintf(stdout, "not listed: %s\n", cli.Text(err.Error()))
			failures = append(failures, err)
			continue
		}
		printEndpoints(stdout, endpoints)
	}
	return errors.Join(failures...)
}

func address(ip netip.Addr, port uint16) string {
	if !ip.IsValid() {
		return cli.Unreadable + ":" + strconv.Itoa(int(port))
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))
}

func printEndpoints(w io.Writer, endpoints []network.Endpoint) {
	fmt.Fprintf(w, "%d endpoints\n", len(endpoints))
	tw := cli.NewTable(w)
	fmt.Fprintln(tw, "Protocol\tFamily\tLocal\tRemote\tState\tPID\tProcess\tCreated")
	for _, e := range endpoints {
		remote, state := "-", "-"
		if e.Kind == network.KindConnection {
			remote = address(e.RemoteIP, e.RemotePort)
		}
		if e.State != "" {
			state = cli.Text(string(e.State))
		}
		pid, owner := "-", "-"
		if e.OwnerProblem == "" {
			pid, owner = strconv.FormatUint(e.OwningPID, 10), cli.Text(e.OwnerImage)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", protocol(e), cli.Text(string(e.Family)),
			address(e.LocalIP, e.LocalPort), remote, state, pid, owner, cli.Time(e.CreateTime, false))
	}
	tw.Flush()
}

func protocol(e network.Endpoint) string {
	if p := e.Kind.Protocol(); p != "" {
		return p
	}
	return cli.Text(string(e.Kind))
}

func netText(t socketlist.Text) string {
	if !t.Available {
		return "-"
	}
	return cli.Text(t.Value)
}

func socketAddress(addr, port socketlist.Text) string {
	if addr.Available && port.Available {
		return net.JoinHostPort(cli.Text(addr.Value), cli.Text(port.Value))
	}
	return netText(addr)
}

func printSockets(w io.Writer, sockets []socketlist.Socket, all bool) {
	tw := cli.NewTable(w)
	fmt.Fprintln(tw, "PID\tProcess\tFD\tFamily\tType\tProtocol\tLocal\tRemote\tState")
	for _, s := range sockets {
		if !all && s.Family != "AF_INET" && s.Family != "AF_INET6" {
			continue
		}
		fmt.Fprintf(tw, "%d\t%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s\n", s.PID, cli.Text(s.Process), s.FD, cli.Text(s.Family),
			cli.Text(s.Type), netText(s.Protocol), socketAddress(s.LocalAddress, s.LocalPort),
			socketAddress(s.RemoteAddress, s.RemotePort), netText(s.State))
	}
	tw.Flush()
}
