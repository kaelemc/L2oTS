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
	intfMatchPattern = "eth%d"
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

		fmt.Printf("%s", intfName)

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
		return fmt.Errorf("failed to bind unix socket to interface %s: %v", iface.name, err)
	}

	return nil
}

// local veth -> tailscale remote peer
func (iface *IFaceL2) fwdToVXLAN() {

	logger.Info("Starting interface to VXLAN forwarder", "interface", iface.index)

	for {
		readBuf := make([]byte, 1500)
		n, err := unix.Read(iface.socketFd, readBuf)
		if err != nil {
			logger.Fatal(err)
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

		err = gopacket.SerializeLayers(vxlBuf, vxlOpts, vxlan, gopacket.Payload(readBuf))
		if err != nil {
			log.Fatal(err)
			continue
		}
		logger.Debug("Serialized frame... Writing", "interface", iface.name, "bytes", len(vxlBuf.Bytes()))

		tsConn.WriteTo(vxlBuf.Bytes(), peer)
	}
}

// Tailscale remote peer -> local veth
func fwdFromVXLAN() {

	logger.Info("Starting VXLAN to interface forwarder")

	for {
		readBuf := make([]byte, 1500)
		n, _, err := tsConn.ReadFrom(readBuf)
		if err != nil {
			logger.Fatal(err)
			continue
		}

		rawVXLAN := readBuf[:n]
		logger.Debug("Got VXLAN packet from Tailscale", "bytes", len(rawVXLAN))

		packet := gopacket.NewPacket(rawVXLAN, layers.LayerTypeVXLAN, gopacket.Default)
		vxlLayer := packet.Layer(layers.LayerTypeVXLAN)
		if vxlLayer == nil {
			logger.Fatal(err)
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
		ethFrame := packet.ApplicationLayer().LayerContents()

		if ethFrame == nil {
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

		unix.Write(outIf.socketFd, ethFrame)
	}
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	logger = log.New(os.Stderr)

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

	peer = &net.UDPAddr{
		IP:   net.ParseIP(_peer),
		Port: vxlanPort,
	}

	logger.Info("Peer defined", "peer", _peer, "port", vxlanPort)

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

	isEphemeral := false
	if len(os.Getenv("EPHEMERAL")) > 0 {
		isEphemeral = true
	}
	logger.Info("Ephemeral status", "ephemeral", isEphemeral)

	// start tailscale server
	tsServer := &tsnet.Server{
		Dir:       tsServerWorkDir,
		Hostname:  hostname,
		Ephemeral: isEphemeral,
		AuthKey:   authKey,
	}
	defer tsServer.Close()

	tsConn, err := tsServer.ListenPacket("udp", fmt.Sprintf("%s:%d", peer.IP.String(), peer.Port))
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

		interfaces = append(interfaces, &IFaceL2{
			name:     name,
			index:    intf.Attrs().Index,
			socketFd: -1,
			vni:      vni,
		})
	}

	<-ctx.Done()
	logger.Info("Stopping")
}
