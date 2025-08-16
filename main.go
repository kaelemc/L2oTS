package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"syscall"
	"time"

	charmlog "github.com/charmbracelet/log"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"tailscale.com/tsnet"
)

var (
	logger     *charmlog.Logger
	peer       net.Addr
	interfaces []*IFaceL2
)

const (
	intfMatchPattern = `eth\d+`
	tsServerWorkDir  = "/var/lib/tsl2/"
	mtu              = 1500
)

type IFaceL2 struct {
	name      string
	index     int
	socketFd  int
	circuitID uint16 // virtual circuit ID -> UDP port
	tsConn    *net.PacketConn
	done      chan struct{}
}

func parseInterfaces() ([]netlink.Link, error) {

	filtered := []netlink.Link{}

	interfaces, err := netlink.LinkList()
	if err != nil {
		return filtered, err
	}

	expr, err := regexp.Compile(intfMatchPattern)
	if err != nil {
		return filtered, err
	}

	for _, intf := range interfaces {
		intfName := intf.Attrs().Name

		// staticlly skip the mgmt intf
		if intfName == "eth0" {
			continue
		}

		logger.Debugf("%s", intfName)

		match := expr.MatchString(intfName)
		if match {
			filtered = append(filtered, intf)
		}
	}

	return filtered, nil
}

// helper for network order bytes
func htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, i)
	return binary.BigEndian.Uint16(b)
}

func (iface *IFaceL2) bindIntfToSocket() error {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return fmt.Errorf("failed creating unix socket for %s: %v", iface.name, err)
	}
	iface.socketFd = fd

	sa := &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  iface.index,
	}

	err = unix.Bind(fd, sa)
	if err != nil {
		unix.Close(fd)
		iface.socketFd = -1
		return fmt.Errorf("failed to bind unix socket to interface %s: %v", iface.name, err)
	}

	mreq := unix.PacketMreq{
		Ifindex: int32(iface.index),
		Type:    unix.PACKET_MR_PROMISC,
	}

	err = unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &mreq)
	if err != nil {
		unix.Close(fd)
		return fmt.Errorf("failed to set promiscuous mode for %s: %v", iface.name, err)
	}

	return nil
}

func (iface *IFaceL2) closeSocket() {
	if iface.socketFd >= 0 {
		unix.Close(iface.socketFd)
		iface.socketFd = -1
	}
}

// forward a frame received on the local itf (unix socket)
// with L2oUDP via tailscale
func (iface *IFaceL2) l2FwdLoop() {
	logger.Info("starting local->remote forwarder", "interface", iface.name, "id", iface.circuitID)
	defer iface.closeSocket()

	buf := make([]byte, mtu)
	for {
		select {
		case <-iface.done:
			return
		default:
		}

		n, err := unix.Read(iface.socketFd, buf)
		if err != nil {
			logger.Error("Failed to read from socket", "interface", iface.name, "error", err)
			break
		}
		if n <= 0 || n > mtu {
			continue
		}

		frame := buf[:n]
		logger.Debug("Got frame", "interface", iface.name, "bytes", len(frame))

		// build UDP header
		sBuf := gopacket.NewSerializeBuffer()
		sOpts := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: false,
		}

		port := layers.UDPPort(iface.circuitID)

		udp := &layers.UDP{
			DstPort: port,
			Length:  uint16(n + 8), // UDP header is 8 bytes
		}

		err = gopacket.SerializeLayers(sBuf, sOpts, udp, gopacket.Payload(frame))
		if err != nil {
			logger.Error("Failed to serialize UDP frame", "interface", iface.name, "error", err)
			continue
		}
		logger.Debug("Serialized frame... Writing", "interface", iface.name, "bytes", len(sBuf.Bytes()))

		if iface.tsConn == nil {
			logger.Error("tsConn is nil", "interface", iface.name)
			continue
		}
		tsConn := *iface.tsConn

		_, err = tsConn.WriteTo(sBuf.Bytes(), peer)
		if err != nil {
			logger.Error("Failed to write to tailscale connection", "interface", iface.name, "error", err)
		}

	}
}

func (iface *IFaceL2) l2RecvLoop() {
	logger.Info("starting remote->local forwarder", "interface", iface.name, "id", iface.circuitID)
	defer iface.closeSocket()

	buf := make([]byte, mtu)
	for {
		select {
		case <-iface.done:
			return
		default:
		}

		if iface.tsConn == nil {
			logger.Error("tsConn is nil", "interface", iface.name)
			return
		}
		tsConn := *iface.tsConn
		n, _, err := tsConn.ReadFrom(buf)
		if err != nil {
			logger.Error("Failed to read from socket", "interface", iface.name, "error", err)
			break
		}
		if n <= 0 || n > mtu {
			continue
		}

		frame := buf[:n]
		logger.Debug("Got frame", "interface", iface.name, "bytes", len(frame))

		packet := gopacket.NewPacket(frame, layers.LayerTypeUDP, gopacket.Default)
		udpLayer := packet.Layer(layers.LayerTypeUDP)

		udp, ok := udpLayer.(*layers.UDP)
		if !ok {
			logger.Error("failed to cast UDP layer")
			continue
		}

		port := udp.DstPort
		if port != layers.UDPPort(iface.circuitID) {
			logger.Error("Mismatch port receieved", "interface", iface.name, "recvPort", port, "wanted", iface.circuitID)
			continue
		}

		appLayer := packet.ApplicationLayer()
		if appLayer == nil {
			logger.Error("No application layer found")
			continue
		}

		ethFrame := appLayer.LayerContents()
		if len(ethFrame) == 0 {
			logger.Error("No L2 payload received")
			continue
		}

		_, err = unix.Write(iface.socketFd, ethFrame)
		if err != nil {
			logger.Error("Failed to write frame to interface", "interface", iface.name, "error", err)
		}
	}

}

func resolveMagicDNS(ctx context.Context, tsServer *tsnet.Server, hostname string) (net.IP, error) {
	localClient, err := tsServer.LocalClient()
	if err != nil {
		return nil, fmt.Errorf("failed to get local client: %w", err)
	}

	status, err := localClient.Status(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get status: %w", err)
	}

	for _, peer := range status.Peer {
		if peer.DNSName == hostname || peer.HostName == hostname {
			if len(peer.TailscaleIPs) > 0 {
				return net.ParseIP(peer.TailscaleIPs[0].String()), nil
			}
		}
	}

	return nil, fmt.Errorf("peer %s not found in magicDNS", hostname)
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	logger = charmlog.New(os.Stdout)

	logger.Info("tsl2 started")

	if len(os.Getenv("DEBUG")) > 0 {
		logger.Info("Debug flag enabled")
		logger.SetLevel(charmlog.DebugLevel)
	}

	_peer := os.Getenv("PEER")
	if len(_peer) == 0 {
		logger.Error("Remote peer must be defined using 'PEER' environment variable")
		return
	}

	logger.Info("Peer hostname", "peer", _peer)

	authKey := os.Getenv("AUTH_KEY")
	if len(authKey) == 0 {
		logger.Warn("No auth key defined. Use 'AUTH_KEY' environment variable, or watch stdout for sign-in link.")
	}

	hostname, err := os.Hostname()
	if err != nil {
		logger.Fatal(err.Error())
		return
	}
	logger.Info("Got hostname", "hostname", hostname)

	isEphemeral := true
	if len(os.Getenv("NO_EPHEMERAL")) > 0 {
		isEphemeral = false
	}
	logger.Info("Ephemeral status", "ephemeral", isEphemeral)

	// start tailscale server
	tsServer := &tsnet.Server{
		Dir:       tsServerWorkDir,
		Hostname:  hostname,
		Ephemeral: isEphemeral,
		AuthKey:   authKey,
		UserLogf:  log.Printf,
		// Logf:      log.Printf,
	}
	defer tsServer.Close()
	_, err = tsServer.Up(ctx)
	if err != nil {
		logger.Fatal("Failed to bring tailscale up")
		return
	}

	// Keep trying to resolve peer until found
	logger.Info("Waiting for peer to be available in MagicDNS", "peer", _peer)
	var peerIP net.IP
	for {
		select {
		case <-ctx.Done():
			logger.Fatal("Context cancelled while waiting for peer")
			return
		default:
			var err error
			peerIP, err = resolveMagicDNS(ctx, tsServer, _peer)
			if err == nil {
				logger.Info("Successfully resolved peer", "peer", _peer, "ip", peerIP)
				break
			}
			logger.Info("Peer not found in MagicDNS, retrying...", "peer", _peer, "error", err)
			time.Sleep(5 * time.Second)
		}
		if peerIP != nil {
			break
		}
	}

	peer = &net.IPAddr{
		IP: peerIP,
	}

	logger.Info("Resolved peer", "peer", _peer, "ip", peerIP)

	tsV4Addr, _ := tsServer.TailscaleIPs()

	localInterfaces, err := parseInterfaces()
	if err != nil {
		logger.Error("Error parsing interfaces", "err", err.Error())
		return
	}
	if len(localInterfaces) == 0 {
		logger.Warn("No data path interfaces found")
	}

	expr, _ := regexp.Compile(`\d+`)
	for _, intf := range localInterfaces {

		name := intf.Attrs().Name

		match := expr.FindString(name)
		num, err := strconv.Atoi(match)
		if err != nil {
			logger.Error("Could not match digits to create VNI", "interface", name)
			continue
		}

		id := uint16(num)
		logger.Debug("Generated virtual circuit id", "interface", name, "id", id)

		tsConn, err := tsServer.ListenPacket("udp4", fmt.Sprintf("%s:%d", tsV4Addr, id))
		if err != nil {
			logger.Fatal(err.Error())
			return
		}

		l2IfaceObj := &IFaceL2{
			name:      name,
			index:     intf.Attrs().Index,
			socketFd:  -1,
			circuitID: id,
			tsConn:    &tsConn,
			done:      make(chan struct{}),
		}
		defer tsConn.Close()

		err = l2IfaceObj.bindIntfToSocket()
		if err != nil {
			logger.Error("Failed to bind interface to socket", "interface", name, "error", err)
			continue
		} else {
			logger.Info("Successfully bound interface to unix socket", "interface", name)
		}

		interfaces = append(interfaces, l2IfaceObj)
	}

	for _, intf := range interfaces {
		go intf.l2FwdLoop()
		go intf.l2RecvLoop()
	}

	<-ctx.Done()
	logger.Info("Stopping")

	for _, intf := range interfaces {
		close(intf.done)
		intf.closeSocket()
	}
}
