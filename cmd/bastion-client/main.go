package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// bastion-client: lightweight tunnel agent
// Runs on your home server, connects outbound to Bastion server via WireGuard.
// Zero inbound ports needed. No kernel modules.
//
// Usage: bastion-client
// Config: bastion-client.json in current directory

type ClientConfig struct {
	ServerEndpoint string           `json:"server_endpoint"` // bastion.example.com:51820
	ServerPubKey   string           `json:"server_pubkey"`
	TunnelIP       string           `json:"tunnel_ip"`       // assigned by server
	PrivateKey     string           `json:"private_key"`     // auto-generated on first run
	Services       []ServiceMapping `json:"services"`
}

type ServiceMapping struct {
	RemotePort int    `json:"remote_port"` // port on tunnel side
	LocalAddr  string `json:"local_addr"`  // e.g. "localhost:3000"
	Name       string `json:"name"`
}

const configFile = "bastion-client.json"

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	fmt.Println("bastion-client v0.1.0 — tunnel agent")

	// Generate config on first run
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		generateConfig()
		return
	}

	cfgData, err := os.ReadFile(configFile)
	if err != nil {
		log.Fatal("Read config: ", err)
	}
	var cfg ClientConfig
	if err := json.Unmarshal(cfgData, &cfg); err != nil {
		log.Fatal("Parse config: ", err)
	}

	if cfg.ServerEndpoint == "" || cfg.ServerPubKey == "" || cfg.TunnelIP == "" {
		log.Fatal("Config incomplete — fill in server_endpoint, server_pubkey, and tunnel_ip")
	}

	privKey, err := wgtypes.ParseKey(cfg.PrivateKey)
	if err != nil {
		log.Fatal("Invalid private key: ", err)
	}

	serverPubKey, err := wgtypes.ParseKey(cfg.ServerPubKey)
	if err != nil {
		log.Fatal("Invalid server pubkey: ", err)
	}

	// Create userspace WireGuard tunnel — no kernel module needed
	tun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr(cfg.TunnelIP)},
		nil, 1420,
	)
	if err != nil {
		log.Fatal("Create TUN: ", err)
	}

	dev := device.NewDevice(tun, conn.NewDefaultBind(),
		device.NewLogger(device.LogLevelError, "bastion-client: "))

	ipcConfig := fmt.Sprintf(
		"private_key=%s\npublic_key=%s\nallowed_ip=10.0.0.0/24\nendpoint=%s\npersistent_keepalive_interval=25\n",
		hex.EncodeToString(privKey[:]),
		hex.EncodeToString(serverPubKey[:]),
		cfg.ServerEndpoint,
	)
	if err := dev.IpcSet(ipcConfig); err != nil {
		log.Fatal("IPC set: ", err)
	}
	if err := dev.Up(); err != nil {
		log.Fatal("Device up: ", err)
	}
	defer dev.Close()

	log.Printf("Tunnel UP: %s → %s", cfg.TunnelIP, cfg.ServerEndpoint)

	// Start proxy listeners on the tunnel for each service
	var wg sync.WaitGroup
	for _, svc := range cfg.Services {
		wg.Add(1)
		go func(s ServiceMapping) {
			defer wg.Done()
			listener, err := tnet.ListenTCP(&net.TCPAddr{Port: s.RemotePort})
			if err != nil {
				log.Printf("Listen tunnel:%d failed: %v", s.RemotePort, err)
				return
			}
			log.Printf("  %s: tunnel:%d → %s", s.Name, s.RemotePort, s.LocalAddr)
			for {
				tunnelConn, err := listener.Accept()
				if err != nil {
					log.Printf("Accept: %v", err)
					continue
				}
				go proxyConn(tunnelConn, s.LocalAddr)
			}
		}(svc)
	}

	log.Println("All services proxied. Press Ctrl+C to stop.")
	wg.Wait()
}

func proxyConn(src net.Conn, targetAddr string) {
	defer src.Close()
	dst, err := net.Dial("tcp", targetAddr)
	if err != nil {
		return
	}
	defer dst.Close()
	go io.Copy(dst, src)
	io.Copy(src, dst)
}

func generateConfig() {
	privKey, _ := wgtypes.GeneratePrivateKey()
	cfg := ClientConfig{
		ServerEndpoint: "your-bastion-server.com:51820",
		ServerPubKey:   "",
		TunnelIP:       "",
		PrivateKey:     privKey.String(),
		Services: []ServiceMapping{
			{RemotePort: 3000, LocalAddr: "localhost:3000", Name: "my-app"},
		},
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	os.WriteFile(configFile, data, 0600)
	fmt.Printf("Generated %s with new private key\n", configFile)
	fmt.Printf("Public key: %s\n", privKey.PublicKey().String())
	fmt.Println("\nNext steps:")
	fmt.Println("1. Register this public key with your Bastion server")
	fmt.Println("2. Fill in server_endpoint, server_pubkey, and tunnel_ip")
	fmt.Println("3. Run bastion-client again")
}
