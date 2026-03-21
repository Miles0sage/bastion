package tunnel

import (
	"encoding/json"
	"net/http"
)

// RegisterRequest is the payload for peer registration
type RegisterRequest struct {
	PublicKey string `json:"public_key"`
	Name      string `json:"name"`
}

// RegisterResponse is returned to the client after registration
type RegisterResponse struct {
	TunnelIP       string `json:"tunnel_ip"`
	ServerPubKey   string `json:"server_pubkey"`
	ServerEndpoint string `json:"server_endpoint"`
	ListenPort     int    `json:"listen_port"`
}

// APIHandler returns HTTP handlers for tunnel management
func APIHandler(ts *TunnelServer, serverEndpoint string) http.Handler {
	mux := http.NewServeMux()

	// Register a new tunnel peer
	mux.HandleFunc("/api/tunnel/register", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}

		var req RegisterRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}

		peer, err := ts.RegisterPeer(req.PublicKey, req.Name)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		resp := RegisterResponse{
			TunnelIP:       peer.TunnelIP.String(),
			ServerPubKey:   ts.PublicKey(),
			ServerEndpoint: serverEndpoint,
			ListenPort:     ts.listenPort,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	// List all peers
	mux.HandleFunc("/api/tunnel/peers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ts.ListPeers())
	})

	// Server info (public key, listen port)
	mux.HandleFunc("/api/tunnel/info", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"public_key":  ts.PublicKey(),
			"listen_port": ts.listenPort,
			"endpoint":    serverEndpoint,
			"peers":       len(ts.ListPeers()),
		})
	})

	return mux
}
