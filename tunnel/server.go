package tunnel

import (
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// TunnelServer manages WireGuard peers and provides net.Conn through the tunnel
type TunnelServer struct {
	mu         sync.RWMutex
	privateKey wgtypes.Key
	listenPort int
	dev        *device.Device
	tnet       *netstack.Net
	peers      map[string]*Peer
	nextIP     byte
}

// Peer represents a connected tunnel client
type Peer struct {
	PublicKey string     `json:"public_key"`
	TunnelIP  netip.Addr `json:"tunnel_ip"`
	Name      string     `json:"name"`
}

// NewServer creates a new WireGuard tunnel server
func NewServer(listenPort int) (*TunnelServer, error) {
	privKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	return &TunnelServer{
		privateKey: privKey,
		listenPort: listenPort,
		peers:      make(map[string]*Peer),
		nextIP:     2, // server is 10.0.0.1, clients start at .2
	}, nil
}

// Start initializes the WireGuard device in userspace (no kernel module)
func (ts *TunnelServer) Start() error {
	tun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr("10.0.0.1")},
		nil,
		1420,
	)
	if err != nil {
		return fmt.Errorf("create tun: %w", err)
	}
	ts.tnet = tnet

	dev := device.NewDevice(tun, conn.NewDefaultBind(),
		device.NewLogger(device.LogLevelError, "bastion-wg: "))

	ipcConfig := fmt.Sprintf("private_key=%s\nlisten_port=%d\n",
		hex.EncodeToString(ts.privateKey[:]),
		ts.listenPort,
	)
	if err := dev.IpcSet(ipcConfig); err != nil {
		return fmt.Errorf("ipc set: %w", err)
	}
	if err := dev.Up(); err != nil {
		return fmt.Errorf("device up: %w", err)
	}
	ts.dev = dev
	log.Printf("WireGuard tunnel listening on :%d", ts.listenPort)
	return nil
}

// PublicKey returns the server's public key for client configuration
func (ts *TunnelServer) PublicKey() string {
	return ts.privateKey.PublicKey().String()
}

// RegisterPeer adds a new tunnel client
func (ts *TunnelServer) RegisterPeer(clientPubKeyStr, name string) (*Peer, error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	pubKey, err := wgtypes.ParseKey(clientPubKeyStr)
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %w", err)
	}

	tunnelIP := netip.AddrFrom4([4]byte{10, 0, 0, ts.nextIP})
	ts.nextIP++

	peer := &Peer{
		PublicKey: clientPubKeyStr,
		TunnelIP:  tunnelIP,
		Name:      name,
	}
	ts.peers[clientPubKeyStr] = peer

	peerConfig := fmt.Sprintf(
		"public_key=%s\nallowed_ip=%s/32\npersistent_keepalive_interval=25\n",
		hex.EncodeToString(pubKey[:]),
		tunnelIP.String(),
	)
	if err := ts.dev.IpcSet(peerConfig); err != nil {
		return nil, fmt.Errorf("add peer: %w", err)
	}

	log.Printf("Tunnel peer registered: %s (%s) -> %s", name, clientPubKeyStr[:8]+"...", tunnelIP)
	return peer, nil
}

// DialPeer connects to a service on a tunnel peer
func (ts *TunnelServer) DialPeer(tunnelAddr string) (net.Conn, error) {
	return ts.tnet.Dial("tcp", tunnelAddr)
}

// ListPeers returns all registered peers
func (ts *TunnelServer) ListPeers() []*Peer {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	peers := make([]*Peer, 0, len(ts.peers))
	for _, p := range ts.peers {
		peers = append(peers, p)
	}
	return peers
}

// Stop shuts down the WireGuard device
func (ts *TunnelServer) Stop() {
	if ts.dev != nil {
		ts.dev.Close()
	}
}
