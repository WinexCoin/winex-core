package nodecore

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ==================== 1. UPNP IGD AUTOMATIC PORT FORWARDING ====================

func TryAutoUPnP(port int) {
	go func() {
		defer func() { _ = recover() }()
		// SSDP M-SEARCH broadcast to discover home router
		ssdpReq := "M-SEARCH * HTTP/1.1\r\n" +
			"HOST: 239.255.255.250:1900\r\n" +
			"ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n" +
			"MAN: \"ssdp:discover\"\r\n" +
			"MX: 2\r\n\r\n"

		raddr, err := net.ResolveUDPAddr("udp4", "239.255.255.250:1900")
		if err != nil {
			return
		}
		conn, err := net.ListenUDP("udp4", nil)
		if err != nil {
			return
		}
		defer conn.Close()

		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = conn.WriteTo([]byte(ssdpReq), raddr)

		buf := make([]byte, 2048)
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		resp := string(buf[:n])

		// Extract Location header
		var loc string
		for _, line := range strings.Split(resp, "\r\n") {
			lower := strings.ToLower(line)
			if strings.HasPrefix(lower, "location:") {
				loc = strings.TrimSpace(line[len("location:"):])
				break
			}
		}
		if loc == "" {
			return
		}

		// Query router device description
		httpClient := &http.Client{Timeout: 3 * time.Second}
		descResp, err := httpClient.Get(loc)
		if err != nil {
			return
		}
		descBody, _ := io.ReadAll(io.LimitReader(descResp.Body, 65536))
		descResp.Body.Close()

		// Look for WANIPConnection or WANPPPConnection control URL
		controlURL := extractControlURL(string(descBody), loc)
		if controlURL == "" {
			return
		}

		// Get local private IP facing the router
		localIP := getLocalOutboundIP()
		if localIP == "" {
			return
		}

		// Send AddPortMapping SOAP request
		soapMsg := fmt.Sprintf(`<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body>
<u:AddPortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
  <NewRemoteHost></NewRemoteHost>
  <NewExternalPort>%d</NewExternalPort>
  <NewProtocol>TCP</NewProtocol>
  <NewInternalPort>%d</NewInternalPort>
  <NewInternalClient>%s</NewInternalClient>
  <NewEnabled>1</NewEnabled>
  <NewPortMappingDescription>WINEX-P2P-Node</NewPortMappingDescription>
  <NewLeaseDuration>0</NewLeaseDuration>
</u:AddPortMapping>
</s:Body>
</s:Envelope>`, port, port, localIP)

		req, err := http.NewRequest("POST", controlURL, bytes.NewBufferString(soapMsg))
		if err == nil {
			req.Header.Set("Content-Type", "text/xml; charset=\"utf-8\"")
			req.Header.Set("SOAPAction", "\"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"")
			if respMap, errMap := httpClient.Do(req); errMap == nil {
				respMap.Body.Close()
				fmt.Printf(" \033[38;2;16;185;129m[UPnP]\033[0m Successfully opened router port %d via UPnP for %s\n", port, localIP)
			}
		}
	}()
}

func extractControlURL(xmlBody, baseLoc string) string {
	type Service struct {
		ServiceType string `xml:"serviceType"`
		ControlURL  string `xml:"controlURL"`
	}
	type Device struct {
		Services []Service `xml:"serviceList>service"`
	}
	type Root struct {
		XMLName xml.Name `xml:"root"`
		Device  Device   `xml:"device"`
	}

	var r Root
	if err := xml.Unmarshal([]byte(xmlBody), &r); err != nil {
		if idx := strings.Index(xmlBody, "<controlURL>"); idx != -1 {
			end := strings.Index(xmlBody[idx:], "</controlURL>")
			if end != -1 {
				raw := xmlBody[idx+len("<controlURL>") : idx+end]
				if strings.HasPrefix(raw, "http") {
					return raw
				}
				u, _ := net.ResolveTCPAddr("tcp", baseLoc)
				_ = u
				if strings.HasPrefix(baseLoc, "http") {
					parts := strings.Split(baseLoc, "/")
					if len(parts) >= 3 {
						return parts[0] + "//" + parts[2] + "/" + strings.TrimPrefix(raw, "/")
					}
				}
			}
		}
		return ""
	}

	for _, s := range r.Device.Services {
		if strings.Contains(s.ServiceType, "WANIPConnection") || strings.Contains(s.ServiceType, "WANPPPConnection") {
			cURL := s.ControlURL
			if strings.HasPrefix(cURL, "http") {
				return cURL
			}
			parts := strings.Split(baseLoc, "/")
			if len(parts) >= 3 {
				return parts[0] + "//" + parts[2] + "/" + strings.TrimPrefix(cURL, "/")
			}
		}
	}
	return ""
}

func getLocalOutboundIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

// ==================== 2. LAN AUTOMATIC ZERO-CONFIG DISCOVERY (mDNS / UDP Broadcast) ====================

const lanDiscoveryPort = 8082

func StartLANAutoDiscovery(nodeEngine *NodeEngine, localListenPort int) {
	// Broadcast announcer
	go func() {
		defer func() { _ = recover() }()
		bcastAddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("255.255.255.255:%d", lanDiscoveryPort))
		if err != nil {
			return
		}
		conn, err := net.ListenUDP("udp4", nil)
		if err != nil {
			return
		}
		defer conn.Close()

		localIP := getLocalOutboundIP()
		announceMsg := fmt.Sprintf("WINEX_P2P:%s:%d", localIP, localListenPort)

		for {
			_, _ = conn.WriteTo([]byte(announceMsg), bcastAddr)
			time.Sleep(8 * time.Second)
		}
	}()

	// Discovery listener
	go func() {
		defer func() { _ = recover() }()
		laddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("0.0.0.0:%d", lanDiscoveryPort))
		if err != nil {
			return
		}
		conn, err := net.ListenUDP("udp4", laddr)
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 512)
		localIP := getLocalOutboundIP()

		for {
			n, _, err := conn.ReadFrom(buf)
			if err != nil {
				time.Sleep(1 * time.Second)
				continue
			}
			msg := string(buf[:n])
			if strings.HasPrefix(msg, "WINEX_P2P:") {
				parts := strings.Split(msg, ":")
				if len(parts) == 3 {
					remoteIP := parts[1]
					remotePort, _ := strconv.Atoi(parts[2])
					if remoteIP != localIP && remotePort > 0 {
						peerURL := fmt.Sprintf("http://%s:%d", remoteIP, remotePort)
						nodeEngine.mu.Lock()
						exists := false
						for _, p := range nodeEngine.state.Peers {
							if p == peerURL {
								exists = true
								break
							}
						}
						if !exists && len(nodeEngine.state.Peers) < 64 {
							nodeEngine.state.Peers = append(nodeEngine.state.Peers, peerURL)
							nodeEngine.saveToDisk()
							fmt.Printf(" \033[38;2;16;185;129m[LAN Discovery]\033[0m Found peer on local network: %s\n", peerURL)
						}
						nodeEngine.mu.Unlock()
					}
				}
			}
		}
	}()
}

// ==================== 3. STUN PUBLIC IP & HOLE PUNCHING ====================

func DiscoverPublicIPViaSTUN() string {
	stunServers := []string{
		"stun.l.google.com:19302",
		"stun1.l.google.com:19302",
		"stun.cloudflare.com:3478",
	}

	for _, srv := range stunServers {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		var d net.Dialer
		conn, err := d.DialContext(ctx, "udp4", srv)
		if err != nil {
			cancel()
			continue
		}

		// STUN Binding Request (RFC 5389): 20 bytes header
		// Type: 0x0001 (Binding Request), Length: 0x0000, Magic Cookie: 0x2112A442, Transaction ID: 12 random bytes
		packet := []byte{
			0x00, 0x01, 0x00, 0x00,
			0x21, 0x12, 0xA4, 0x42,
			0x98, 0x76, 0x54, 0x32, 0x10, 0xAB, 0xCD, 0xEF, 0x11, 0x22, 0x33, 0x44,
		}

		_ = conn.SetDeadline(time.Now().Add(1500 * time.Millisecond))
		_, _ = conn.Write(packet)

		res := make([]byte, 512)
		n, err := conn.Read(res)
		conn.Close()
		cancel()

		if err == nil && n >= 28 {
			// Search for XOR-MAPPED-ADDRESS attribute (0x0020)
			for i := 20; i < n-8; {
				attrType := uint16(res[i])<<8 | uint16(res[i+1])
				attrLen := int(uint16(res[i+2])<<8 | uint16(res[i+3]))
				if attrType == 0x0020 && attrLen >= 8 {
					// IPv4 family: 0x01
					if res[i+5] == 0x01 {
						ip := net.IPv4(
							res[i+8]^0x21,
							res[i+9]^0x12,
							res[i+10]^0xA4,
							res[i+11]^0x42,
						)
						return ip.String()
					}
				}
				i += 4 + attrLen
			}
		}
	}
	return ""
}
