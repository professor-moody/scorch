package auth

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf16"

	"golang.org/x/crypto/md4"
)

// AuthMethod represents the authentication method to use
type AuthMethod int

const (
	AuthNone AuthMethod = iota
	AuthBasic
	AuthNTLM
	AuthNTLMHash  // Pass-the-Hash
	AuthKerberos
	AuthKerberosTicket // Pass-the-Ticket
	AuthNegotiate
)

func (m AuthMethod) String() string {
	switch m {
	case AuthNone:
		return "None"
	case AuthBasic:
		return "Basic"
	case AuthNTLM:
		return "NTLM"
	case AuthNTLMHash:
		return "NTLM-PTH"
	case AuthKerberos:
		return "Kerberos"
	case AuthKerberosTicket:
		return "Kerberos-PTT"
	case AuthNegotiate:
		return "Negotiate"
	default:
		return "Unknown"
	}
}

// Credentials holds authentication credentials
type Credentials struct {
	Username    string
	Password    string
	Domain      string
	NTHash      string     // For Pass-the-Hash (32 hex chars)
	LMHash      string     // Optional LM hash
	Ticket      []byte     // For Pass-the-Ticket (kirbi/ccache)
	TicketPath  string     // Path to ticket file
	Method      AuthMethod
}

// AuthenticatedTransport wraps http.Transport with authentication
type AuthenticatedTransport struct {
	Transport   *http.Transport
	Credentials *Credentials
	TargetSPN   string // Service Principal Name for Kerberos
	Debug       bool
}

// NTLMChallenge holds NTLM challenge data
type NTLMChallenge struct {
	ServerChallenge []byte
	TargetName      string
	TargetInfo      []byte
	Flags           uint32
	Version         []byte
}

// RoundTrip implements http.RoundTripper for authenticated requests
func (t *AuthenticatedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	switch t.Credentials.Method {
	case AuthNone:
		return t.Transport.RoundTrip(req)
	case AuthBasic:
		return t.doBasicAuth(req)
	case AuthNTLM, AuthNTLMHash:
		return t.doNTLMAuth(req)
	case AuthKerberos, AuthKerberosTicket:
		return t.doKerberosAuth(req)
	case AuthNegotiate:
		return t.doNegotiateAuth(req)
	default:
		return t.Transport.RoundTrip(req)
	}
}

// doBasicAuth performs HTTP Basic authentication
func (t *AuthenticatedTransport) doBasicAuth(req *http.Request) (*http.Response, error) {
	username := t.Credentials.Username
	if t.Credentials.Domain != "" {
		username = t.Credentials.Domain + "\\" + t.Credentials.Username
	}
	
	auth := base64.StdEncoding.EncodeToString(
		[]byte(username + ":" + t.Credentials.Password),
	)
	req.Header.Set("Authorization", "Basic "+auth)
	
	return t.Transport.RoundTrip(req)
}

// doNTLMAuth performs NTLM authentication (3-leg handshake)
func (t *AuthenticatedTransport) doNTLMAuth(req *http.Request) (*http.Response, error) {
	// Step 1: Send Type 1 (Negotiate) message
	negotiate := t.createNTLMNegotiate()
	negotiateB64 := base64.StdEncoding.EncodeToString(negotiate)
	
	req1 := cloneRequest(req)
	req1.Header.Set("Authorization", "NTLM "+negotiateB64)
	
	resp1, err := t.Transport.RoundTrip(req1)
	if err != nil {
		return nil, fmt.Errorf("NTLM negotiate failed: %w", err)
	}
	
	// Check for 401 with NTLM challenge
	if resp1.StatusCode != http.StatusUnauthorized {
		return resp1, nil // Might not need auth
	}
	
	// Step 2: Parse Type 2 (Challenge) message
	authHeader := resp1.Header.Get("Www-Authenticate")
	resp1.Body.Close()
	
	if !strings.HasPrefix(authHeader, "NTLM ") {
		return nil, fmt.Errorf("expected NTLM challenge, got: %s", authHeader)
	}
	
	challengeB64 := strings.TrimPrefix(authHeader, "NTLM ")
	challengeBytes, err := base64.StdEncoding.DecodeString(challengeB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode NTLM challenge: %w", err)
	}
	
	challenge, err := t.parseNTLMChallenge(challengeBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse NTLM challenge: %w", err)
	}
	
	if t.Debug {
		fmt.Printf("[NTLM] Challenge received, target: %s\n", challenge.TargetName)
	}
	
	// Step 3: Send Type 3 (Authenticate) message
	var authenticate []byte
	if t.Credentials.Method == AuthNTLMHash {
		// Pass-the-Hash: use NT hash directly
		authenticate, err = t.createNTLMAuthenticatePTH(challenge)
	} else {
		// Normal: compute hash from password
		authenticate, err = t.createNTLMAuthenticate(challenge)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create NTLM authenticate: %w", err)
	}
	
	authenticateB64 := base64.StdEncoding.EncodeToString(authenticate)
	
	req2 := cloneRequest(req)
	req2.Header.Set("Authorization", "NTLM "+authenticateB64)
	
	return t.Transport.RoundTrip(req2)
}

// createNTLMNegotiate creates an NTLM Type 1 message
func (t *AuthenticatedTransport) createNTLMNegotiate() []byte {
	// NTLM Type 1 message structure
	// Signature: "NTLMSSP\0"
	// Type: 1 (uint32)
	// Flags: uint32
	// DomainNameFields: SecurityBuffer (8 bytes)
	// WorkstationFields: SecurityBuffer (8 bytes)
	// Version: 8 bytes (optional)
	
	flags := uint32(
		0x00000001 | // NTLMSSP_NEGOTIATE_UNICODE
		0x00000002 | // NTLM_NEGOTIATE_OEM
		0x00000004 | // NTLMSSP_REQUEST_TARGET
		0x00000200 | // NTLMSSP_NEGOTIATE_NTLM
		0x00008000 | // NTLMSSP_NEGOTIATE_ALWAYS_SIGN
		0x00080000 | // NTLMSSP_NEGOTIATE_NTLM2
		0x02000000 | // NTLMSSP_NEGOTIATE_128
		0x20000000 | // NTLMSSP_NEGOTIATE_56
		0x80000000)  // NTLMSSP_NEGOTIATE_KEY_EXCH

	buf := new(bytes.Buffer)
	buf.WriteString("NTLMSSP\x00")          // Signature
	binary.Write(buf, binary.LittleEndian, uint32(1)) // Type
	binary.Write(buf, binary.LittleEndian, flags)     // Flags
	
	// Domain name fields (empty)
	binary.Write(buf, binary.LittleEndian, uint16(0)) // Len
	binary.Write(buf, binary.LittleEndian, uint16(0)) // MaxLen
	binary.Write(buf, binary.LittleEndian, uint32(0)) // Offset
	
	// Workstation fields (empty)
	binary.Write(buf, binary.LittleEndian, uint16(0)) // Len
	binary.Write(buf, binary.LittleEndian, uint16(0)) // MaxLen
	binary.Write(buf, binary.LittleEndian, uint32(0)) // Offset
	
	return buf.Bytes()
}

// parseNTLMChallenge parses an NTLM Type 2 message
func (t *AuthenticatedTransport) parseNTLMChallenge(data []byte) (*NTLMChallenge, error) {
	if len(data) < 32 {
		return nil, fmt.Errorf("challenge too short: %d bytes", len(data))
	}
	
	// Verify signature
	if string(data[0:8]) != "NTLMSSP\x00" {
		return nil, fmt.Errorf("invalid NTLM signature")
	}
	
	// Verify type
	msgType := binary.LittleEndian.Uint32(data[8:12])
	if msgType != 2 {
		return nil, fmt.Errorf("expected Type 2, got Type %d", msgType)
	}
	
	challenge := &NTLMChallenge{
		Flags: binary.LittleEndian.Uint32(data[20:24]),
	}
	
	// Server challenge is at offset 24, 8 bytes
	challenge.ServerChallenge = make([]byte, 8)
	copy(challenge.ServerChallenge, data[24:32])
	
	// Target name (security buffer at offset 12)
	targetLen := binary.LittleEndian.Uint16(data[12:14])
	targetOffset := binary.LittleEndian.Uint32(data[16:20])
	if targetOffset > 0 && int(targetOffset+uint32(targetLen)) <= len(data) {
		targetBytes := data[targetOffset : targetOffset+uint32(targetLen)]
		challenge.TargetName = utf16ToString(targetBytes)
	}
	
	// Target info (security buffer at offset 40, if present)
	if len(data) >= 48 {
		infoLen := binary.LittleEndian.Uint16(data[40:42])
		infoOffset := binary.LittleEndian.Uint32(data[44:48])
		if infoOffset > 0 && int(infoOffset+uint32(infoLen)) <= len(data) {
			challenge.TargetInfo = make([]byte, infoLen)
			copy(challenge.TargetInfo, data[infoOffset:infoOffset+uint32(infoLen)])
		}
	}
	
	return challenge, nil
}

// createNTLMAuthenticate creates an NTLM Type 3 message with password
func (t *AuthenticatedTransport) createNTLMAuthenticate(challenge *NTLMChallenge) ([]byte, error) {
	// Calculate NT hash from password
	ntHash := ntHashFromPassword(t.Credentials.Password)
	return t.createNTLMAuthenticateWithHash(challenge, ntHash)
}

// createNTLMAuthenticatePTH creates an NTLM Type 3 message with pre-computed hash
func (t *AuthenticatedTransport) createNTLMAuthenticatePTH(challenge *NTLMChallenge) ([]byte, error) {
	// Parse NT hash from hex string
	ntHash, err := parseHexHash(t.Credentials.NTHash)
	if err != nil {
		return nil, fmt.Errorf("invalid NT hash: %w", err)
	}
	return t.createNTLMAuthenticateWithHash(challenge, ntHash)
}

// createNTLMAuthenticateWithHash creates Type 3 message with provided hash
func (t *AuthenticatedTransport) createNTLMAuthenticateWithHash(challenge *NTLMChallenge, ntHash []byte) ([]byte, error) {
	// Generate client challenge (8 random bytes - simplified)
	clientChallenge := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	
	// Calculate NTLMv2 response
	username := strings.ToUpper(t.Credentials.Username)
	domain := strings.ToUpper(t.Credentials.Domain)
	
	// NTLMv2 hash = HMAC-MD5(NT hash, UPPER(username) + domain)
	ntlmv2Hash := hmacMD5(ntHash, toUnicode(username+domain))
	
	// Create blob (simplified)
	timestamp := uint64(time.Now().UnixNano()/100 + 116444736000000000) // Windows FILETIME
	
	blob := new(bytes.Buffer)
	blob.Write([]byte{0x01, 0x01, 0x00, 0x00})      // Version
	blob.Write([]byte{0x00, 0x00, 0x00, 0x00})      // Reserved
	binary.Write(blob, binary.LittleEndian, timestamp)
	blob.Write(clientChallenge)
	blob.Write([]byte{0x00, 0x00, 0x00, 0x00})      // Reserved
	if len(challenge.TargetInfo) > 0 {
		blob.Write(challenge.TargetInfo)
	}
	blob.Write([]byte{0x00, 0x00, 0x00, 0x00})      // Reserved
	
	// Temp = serverChallenge + blob
	temp := append(challenge.ServerChallenge, blob.Bytes()...)
	
	// NTProofStr = HMAC-MD5(NTLMv2 hash, temp)
	ntProofStr := hmacMD5(ntlmv2Hash, temp)
	
	// NTChallengeResponse = ntProofStr + blob
	ntChallengeResponse := append(ntProofStr, blob.Bytes()...)
	
	// Build Type 3 message
	domainUnicode := toUnicode(t.Credentials.Domain)
	usernameUnicode := toUnicode(t.Credentials.Username)
	workstationUnicode := toUnicode("WORKSTATION")
	
	// Calculate offsets
	headerLen := uint32(88) // Fixed header size
	domainOffset := headerLen
	usernameOffset := domainOffset + uint32(len(domainUnicode))
	workstationOffset := usernameOffset + uint32(len(usernameUnicode))
	lmOffset := workstationOffset + uint32(len(workstationUnicode))
	ntOffset := lmOffset + 24 // LM response is 24 bytes (empty/zeros for NTLMv2)
	
	flags := uint32(
		0x00000001 | // NTLMSSP_NEGOTIATE_UNICODE
		0x00000200 | // NTLMSSP_NEGOTIATE_NTLM
		0x00008000 | // NTLMSSP_NEGOTIATE_ALWAYS_SIGN
		0x00080000 | // NTLMSSP_NEGOTIATE_NTLM2
		0x02000000 | // NTLMSSP_NEGOTIATE_128
		0x20000000 | // NTLMSSP_NEGOTIATE_56
		0x80000000)  // NTLMSSP_NEGOTIATE_KEY_EXCH
	
	msg := new(bytes.Buffer)
	msg.WriteString("NTLMSSP\x00")
	binary.Write(msg, binary.LittleEndian, uint32(3)) // Type 3
	
	// LM Response (empty for NTLMv2)
	binary.Write(msg, binary.LittleEndian, uint16(24))
	binary.Write(msg, binary.LittleEndian, uint16(24))
	binary.Write(msg, binary.LittleEndian, lmOffset)
	
	// NT Response
	binary.Write(msg, binary.LittleEndian, uint16(len(ntChallengeResponse)))
	binary.Write(msg, binary.LittleEndian, uint16(len(ntChallengeResponse)))
	binary.Write(msg, binary.LittleEndian, ntOffset)
	
	// Domain
	binary.Write(msg, binary.LittleEndian, uint16(len(domainUnicode)))
	binary.Write(msg, binary.LittleEndian, uint16(len(domainUnicode)))
	binary.Write(msg, binary.LittleEndian, domainOffset)
	
	// Username
	binary.Write(msg, binary.LittleEndian, uint16(len(usernameUnicode)))
	binary.Write(msg, binary.LittleEndian, uint16(len(usernameUnicode)))
	binary.Write(msg, binary.LittleEndian, usernameOffset)
	
	// Workstation
	binary.Write(msg, binary.LittleEndian, uint16(len(workstationUnicode)))
	binary.Write(msg, binary.LittleEndian, uint16(len(workstationUnicode)))
	binary.Write(msg, binary.LittleEndian, workstationOffset)
	
	// Encrypted Random Session Key (empty)
	binary.Write(msg, binary.LittleEndian, uint16(0))
	binary.Write(msg, binary.LittleEndian, uint16(0))
	binary.Write(msg, binary.LittleEndian, uint32(0))
	
	// Flags
	binary.Write(msg, binary.LittleEndian, flags)
	
	// Payload
	msg.Write(domainUnicode)
	msg.Write(usernameUnicode)
	msg.Write(workstationUnicode)
	msg.Write(make([]byte, 24)) // LM response (zeros)
	msg.Write(ntChallengeResponse)
	
	return msg.Bytes(), nil
}

// doKerberosAuth performs Kerberos authentication
func (t *AuthenticatedTransport) doKerberosAuth(req *http.Request) (*http.Response, error) {
	return t.doKerberosAuthImpl(req)
}

// doNegotiateAuth attempts SPNEGO negotiation
func (t *AuthenticatedTransport) doNegotiateAuth(req *http.Request) (*http.Response, error) {
	// Try Kerberos first, fall back to NTLM
	resp, err := t.doKerberosAuth(req)
	if err != nil {
		return t.doNTLMAuth(req)
	}
	return resp, nil
}

// Helper functions

func cloneRequest(req *http.Request) *http.Request {
	clone := req.Clone(req.Context())
	if req.Body != nil {
		// We need to read and restore the body
		body, _ := io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewReader(body))
		clone.Body = io.NopCloser(bytes.NewReader(body))
	}
	return clone
}

func ntHashFromPassword(password string) []byte {
	// MD4 of UTF-16LE encoded password
	unicode := toUnicode(password)
	return md4Hash(unicode)
}

func md4Hash(data []byte) []byte {
	h := md4.New()
	h.Write(data)
	return h.Sum(nil)
}

func hmacMD5(key, data []byte) []byte {
	h := hmac.New(md5.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func toUnicode(s string) []byte {
	runes := utf16.Encode([]rune(s))
	buf := make([]byte, len(runes)*2)
	for i, r := range runes {
		binary.LittleEndian.PutUint16(buf[i*2:], r)
	}
	return buf
}

func utf16ToString(b []byte) string {
	if len(b)%2 != 0 {
		return ""
	}
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u16))
}

func parseHexHash(hexHash string) ([]byte, error) {
	if len(hexHash) != 32 {
		return nil, fmt.Errorf("NT hash must be 32 hex characters, got %d", len(hexHash))
	}
	hash := make([]byte, 16)
	for i := 0; i < 16; i++ {
		_, err := fmt.Sscanf(hexHash[i*2:i*2+2], "%02x", &hash[i])
		if err != nil {
			return nil, fmt.Errorf("invalid hex at position %d: %w", i*2, err)
		}
	}
	return hash, nil
}

// NewAuthenticatedClient creates an HTTP client with authentication
func NewAuthenticatedClient(creds *Credentials, skipVerify bool, timeout time.Duration) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: skipVerify,
		},
	}
	
	authTransport := &AuthenticatedTransport{
		Transport:   transport,
		Credentials: creds,
	}
	
	return &http.Client{
		Transport: authTransport,
		Timeout:   timeout,
	}
}

// ParseCredentials parses credentials from various input formats
func ParseCredentials(username, password, domain, hash, method string) (*Credentials, error) {
	creds := &Credentials{
		Username: username,
		Password: password,
		Domain:   domain,
	}
	
	// Determine auth method
	switch strings.ToLower(method) {
	case "", "auto":
		if hash != "" {
			creds.Method = AuthNTLMHash
			creds.NTHash = hash
		} else if password != "" {
			creds.Method = AuthNTLM
		} else {
			creds.Method = AuthNone
		}
	case "ntlm":
		creds.Method = AuthNTLM
	case "pth", "hash":
		creds.Method = AuthNTLMHash
		creds.NTHash = hash
	case "basic":
		creds.Method = AuthBasic
	case "kerberos":
		creds.Method = AuthKerberos
	case "none", "anonymous":
		creds.Method = AuthNone
	default:
		return nil, fmt.Errorf("unknown auth method: %s", method)
	}
	
	// Parse DOMAIN\username format
	if strings.Contains(username, "\\") && domain == "" {
		parts := strings.SplitN(username, "\\", 2)
		creds.Domain = parts[0]
		creds.Username = parts[1]
	}
	
	// Parse username@DOMAIN format
	if strings.Contains(username, "@") && domain == "" {
		parts := strings.SplitN(username, "@", 2)
		creds.Username = parts[0]
		creds.Domain = parts[1]
	}
	
	// Validate PTH credentials
	if creds.Method == AuthNTLMHash {
		if creds.NTHash == "" {
			return nil, fmt.Errorf("NT hash required for PTH authentication")
		}
		// Handle LM:NT format
		if strings.Contains(creds.NTHash, ":") {
			parts := strings.Split(creds.NTHash, ":")
			if len(parts) >= 2 {
				creds.LMHash = parts[0]
				creds.NTHash = parts[1]
			}
		}
		if len(creds.NTHash) != 32 {
			return nil, fmt.Errorf("NT hash must be 32 hex characters")
		}
	}
	
	return creds, nil
}

// TestAuthentication tests if credentials are valid against a target
func TestAuthentication(ctx context.Context, target string, creds *Credentials) (bool, string, error) {
	client := NewAuthenticatedClient(creds, true, 10*time.Second)
	
	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return false, "", err
	}
	
	resp, err := client.Do(req)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()
	
	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated, http.StatusAccepted:
		return true, fmt.Sprintf("Authentication successful (HTTP %d)", resp.StatusCode), nil
	case http.StatusUnauthorized:
		return false, "Authentication failed (HTTP 401)", nil
	case http.StatusForbidden:
		return false, "Authentication succeeded but access denied (HTTP 403)", nil
	default:
		return false, fmt.Sprintf("Unexpected response (HTTP %d)", resp.StatusCode), nil
	}
}
