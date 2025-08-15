package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"syscall"

	"github.com/charmbracelet/log"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"tailscale.com/tsnet"
)

var (
	logger     *log.Logger
	tsConn     net.PacketConn
	peer       *net.UDPAddr
	interfaces []*IFaceL2
)

const (
	intfMatchPattern = `eth\d+`
	vxlanPort        = 4789
	tsServerWorkDir  = "/var/lib/tsl2/"
)

type IFaceL2 struct {
	name     string
	index    int
	socketFd int
	vni      uint32
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

func (iface *IFaceL2) bindIntfToSocket() error {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, unix.ETH_P_ALL)
	if err != nil {
		return fmt.Errorf("failed creating unix socket for %s: %v", iface.name, err)
	}
	iface.socketFd = fd

	sa := &unix.SockaddrLinklayer{
		Protocol: unix.ETH_P_ALL,
		Ifindex:  iface.index,
	}

	err = unix.Bind(fd, sa)
	if err != nil {
		unix.Close(fd)
		iface.socketFd = -1
		return fmt.Errorf("failed to bind unix socket to interface %s: %v", iface.name, err)
	}

	return nil
}

func (iface *IFaceL2) closeSocket() {
	if iface.socketFd >= 0 {
		unix.Close(iface.socketFd)
		iface.socketFd = -1
	}
}

// local veth -> tailscale remote peer
func (iface *IFaceL2) fwdToVXLAN() {

	logger.Info("Starting interface to VXLAN forwarder", "interface", iface.name, "index", iface.index)

	for {
		readBuf := make([]byte, 1500)
		n, err := unix.Read(iface.socketFd, readBuf)
		if err != nil {
			logger.Error("Failed to read from socket", "interface", iface.name, "error", err)
			break
		}
		if n <= 0 || n > len(readBuf) {
			continue
		}

		frame := readBuf[:n]
		logger.Debug("Got frame", "interface", iface.name, "bytes", len(frame))

		// build the vxlan frame
		vxlBuf := gopacket.NewSerializeBuffer()
		vxlOpts := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}

		vxlan := &layers.VXLAN{
			VNI:         iface.vni,
			ValidIDFlag: true,
		}

		err = gopacket.SerializeLayers(vxlBuf, vxlOpts, vxlan, gopacket.Payload(frame))
		if err != nil {
			logger.Error("Failed to serialize VXLAN frame", "interface", iface.name, "error", err)
			continue
		}
		logger.Debug("Serialized frame... Writing", "interface", iface.name, "bytes", len(vxlBuf.Bytes()))

		_, err = tsConn.WriteTo(vxlBuf.Bytes(), peer)
		if err != nil {
			logger.Error("Failed to write to tailscale connection", "interface", iface.name, "error", err)
		}
	}
}

// Tailscale remote peer -> local veth
func fwdFromVXLAN() {

	logger.Info("Starting VXLAN to interface forwarder")

	for {
		readBuf := make([]byte, 1500)
		n, _, err := tsConn.ReadFrom(readBuf)
		if err != nil {
			logger.Error("Failed to read from tailscale connection", "error", err)
			break
		}
		if n <= 0 || n > len(readBuf) {
			continue
		}

		rawVXLAN := readBuf[:n]
		logger.Debug("Got VXLAN packet from Tailscale", "bytes", len(rawVXLAN))

		packet := gopacket.NewPacket(rawVXLAN, layers.LayerTypeVXLAN, gopacket.Default)
		vxlLayer := packet.Layer(layers.LayerTypeVXLAN)
		if vxlLayer == nil {
			logger.Error("No VXLAN layer found in packet")
			continue
		}

		vxlan, ok := vxlLayer.(*layers.VXLAN)
		if !ok {
			logger.Error("failed to cast VXLAN layer")
			continue
		}

		if !vxlan.ValidIDFlag {
			logger.Error("VXLAN VNI flag not set")
			continue
		}

		vni := vxlan.VNI
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

		var outIf *IFaceL2
		for _, intf := range interfaces {
			if intf.vni == vni {
				outIf = intf
				break
			}
		}

		if outIf == nil {
			logger.Error("Could not match VNI to local interface", "vni", vni)
			continue
		}

		_, err = unix.Write(outIf.socketFd, ethFrame)
		if err != nil {
			logger.Error("Failed to write frame to interface", "interface", outIf.name, "error", err)
		}
	}
}

// tsnet logf adapter to charm
func createLogf(logger *log.Logger, level log.Level) func(format string, args ...interface{}) {
	return func(format string, args ...interface{}) {
		// Format the message like Printf would
		message := fmt.Sprintf(format, args...)
		// Send to charm logger
		logger.Log(level, message)
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

	logger = log.New(os.Stderr)
	tsLogger := log.New(os.Stderr)

	logger.Info("tsl2 started")

	if len(os.Getenv("DEBUG")) > 0 {
		logger.Info("Debug flag enabled")
		logger.SetLevel(log.DebugLevel)
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
		UserLogf:  createLogf(tsLogger, log.InfoLevel),
		Logf:      createLogf(tsLogger, log.DebugLevel),
	}
	defer tsServer.Close()

	// resolve peer hostname using magicDNS
	peerIP, err := resolveMagicDNS(ctx, tsServer, _peer)
	if err != nil {
		logger.Fatal("Failed to resolve peer via magicDNS", "peer", _peer, "error", err)
		return
	}

	peer = &net.UDPAddr{
		IP:   peerIP,
		Port: vxlanPort,
	}

	logger.Info("Resolved peer", "peer", _peer, "ip", peerIP, "port", vxlanPort)

	tsV4Addr, _ := tsServer.TailscaleIPs()
	if !tsV4Addr.IsValid() {
		logger.Fatal("No valid Tailscale IPv4 address available")
		return
	}

	tsConn, err = tsServer.ListenPacket("udp4", fmt.Sprintf("%s:%d", tsV4Addr, vxlanPort))
	if err != nil {
		logger.Fatal(err.Error())
		return
	}
	defer tsConn.Close()

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

		vni := uint32(num)
		logger.Debug("Generated VNI", "interface", name, "vni", vni)

		l2IfaceObj := &IFaceL2{
			name:     name,
			index:    intf.Attrs().Index,
			socketFd: -1,
			vni:      vni,
		}

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
		go intf.fwdToVXLAN()
	}
	go fwdFromVXLAN()

	<-ctx.Done()
	logger.Info("Stopping")

	for _, intf := range interfaces {
		intf.closeSocket()
	}
}
