// Command replay plays rule test fixtures into the gvisor plugin socket as a
// fake sandbox, and verifies Falco's JSON alerts against them.
//
//	replay send -socket /run/falco/gvisor.sock rules/tests/*.json
//	replay verify -log falco.json rules/tests/*.json
package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"google.golang.org/protobuf/proto"
	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
	"gvisor.dev/gvisor/pkg/sentry/seccheck/sinks/remote/wire"

	"github.com/falcosecurity/plugins/plugins/gvisor/internal/fixture"
)

const (
	networkUnixPacket   = "unixpacket"
	handshakeBufferSize = 10240
	ioTimeout           = 5 * time.Second
	cmdSend             = "send"
	cmdVerify           = "verify"
	exitUsage           = 2
)

var errFixturesFailed = errors.New("fixtures failed")

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case cmdSend:
		err = runSend(os.Args[2:])
	case cmdVerify:
		err = runVerify(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: replay send -socket PATH FIXTURE... | replay verify -log FILE FIXTURE...")
	os.Exit(exitUsage)
}

func loadAll(paths []string) ([]fixture.Fixture, error) {
	fixtures := make([]fixture.Fixture, 0, len(paths))
	for _, p := range paths {
		f, err := fixture.Load(p)
		if err != nil {
			return nil, err
		}
		fixtures = append(fixtures, f)
	}
	return fixtures, nil
}

func runSend(args []string) error {
	fs := flag.NewFlagSet(cmdSend, flag.ExitOnError)
	socket := fs.String("socket", "/run/falco/gvisor.sock", "plugin socket")
	_ = fs.Parse(args)
	fixtures, err := loadAll(fs.Args())
	if err != nil {
		return err
	}
	for _, f := range fixtures {
		if err := send(*socket, f); err != nil {
			return fmt.Errorf("%s: %w", f.Name, err)
		}
		fmt.Printf("sent %s (%d events, container %s)\n", f.Name, len(f.Events), f.ContainerID[:12])
	}
	return nil
}

func send(socket string, f fixture.Fixture) error {
	packets, err := f.Packets()
	if err != nil {
		return err
	}
	conn, err := net.DialUnix(networkUnixPacket, nil, &net.UnixAddr{Name: socket, Net: networkUnixPacket})
	if err != nil {
		return fmt.Errorf("dial %s: %w", socket, err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(ioTimeout)); err != nil {
		return err
	}
	if err := handshake(conn); err != nil {
		return err
	}
	for _, pkt := range packets {
		if _, err := conn.Write(pkt); err != nil {
			return fmt.Errorf("write: %w", err)
		}
	}
	return nil
}

func handshake(conn *net.UnixConn) error {
	hs, err := proto.Marshal(&pb.Handshake{Version: wire.CurrentVersion})
	if err != nil {
		return err
	}
	if _, err := conn.Write(hs); err != nil {
		return fmt.Errorf("send handshake: %w", err)
	}
	if _, err := conn.Read(make([]byte, handshakeBufferSize)); err != nil {
		return fmt.Errorf("read handshake: %w", err)
	}
	return nil
}

func runVerify(args []string) error {
	fs := flag.NewFlagSet(cmdVerify, flag.ExitOnError)
	logPath := fs.String("log", "", "file with Falco JSON output")
	_ = fs.Parse(args)
	fixtures, err := loadAll(fs.Args())
	if err != nil {
		return err
	}
	logFile, err := os.Open(*logPath)
	if err != nil {
		return fmt.Errorf("open falco log: %w", err)
	}
	defer func() { _ = logFile.Close() }()
	results, err := fixture.Verify(fixtures, logFile)
	if err != nil {
		return err
	}
	failed := 0
	for _, r := range results {
		fmt.Println(r)
		if !r.OK() {
			failed++
		}
	}
	if failed > 0 {
		return fmt.Errorf("%w: %d of %d", errFixturesFailed, failed, len(results))
	}
	return nil
}
