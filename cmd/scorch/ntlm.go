package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf16"

	"golang.org/x/crypto/md4"
)

// NTLM Flags
const (
	NTLMSSP_NEGOTIATE_UNICODE                  = 0x00000001
	NTLMSSP_NEGOTIATE_OEM                      = 0x00000002
	NTLMSSP_REQUEST_TARGET                     = 0x00000004
	NTLMSSP_NEGOTIATE_SIGN                     = 0x00000010
	NTLMSSP_NEGOTIATE_SEAL                     = 0x00000020
	NTLMSSP_NEGOTIATE_DATAGRAM                 = 0x00000040
	NTLMSSP_NEGOTIATE_LM_KEY                   = 0x00000080
	NTLMSSP_NEGOTIATE_NTLM                     = 0x00000200
	NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED      = 0x00001000
	NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED = 0x00002000
	NTLMSSP_NEGOTIATE_ALWAYS_SIGN              = 0x00008000
	NTLMSSP_TARGET_TYPE_DOMAIN                 = 0x00010000
	NTLMSSP_TARGET_TYPE_SERVER                 = 0x00020000
	NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY = 0x00080000
	NTLMSSP_NEGOTIATE_IDENTIFY                 = 0x00100000
	NTLMSSP_REQUEST_NON_NT_SESSION_KEY         = 0x00400000
	NTLMSSP_NEGOTIATE_TARGET_INFO              = 0x00800000
	NTLMSSP_NEGOTIATE_VERSION                  = 0x02000000
	NTLMSSP_NEGOTIATE_128                      = 0x20000000
	NTLMSSP_NEGOTIATE_KEY_EXCH                 = 0x40000000
	NTLMSSP_NEGOTIATE_56                       = 0x80000000
)

// NTLMAuth handles NTLM authentication
type NTLMAuth struct {
	Domain      string
	User        string
	Password    string
	Hash        string // NT hash as hex string
	Workstation string
	Debug       bool
}

// NTLMHashTransport wraps http.Transport with NTLM pass-the-hash
type NTLMHashTransport struct {
	Transport *http.Transport
	Auth      *NTLMAuth
}

// RoundTrip implements http.RoundTripper with NTLM authentication
func (t *NTLMHashTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// First request to get challenge
	req1 := cloneRequest(req)
	resp, err := t.Transport.RoundTrip(req1)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusUnauthorized {
		return resp, nil
	}

	// Check for NTLM/Negotiate
	authHeader := resp.Header.Get("WWW-Authenticate")
	if !strings.Contains(strings.ToLower(authHeader), "ntlm") &&
		!strings.Contains(strings.ToLower(authHeader), "negotiate") {
		if t.Auth.Debug {
			fmt.Printf("[NTLM] No NTLM/Negotiate in WWW-Authenticate: %s\n", authHeader)
		}
		return resp, nil
	}
	// Must fully read body to allow connection reuse for NTLM
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if t.Auth.Debug {
		fmt.Printf("[NTLM] Starting auth for %s as %s\\%s\n", req.URL.Host, t.Auth.Domain, t.Auth.User)
	}

	// Send Type 1 (Negotiate)
	negotiate := t.Auth.BuildNegotiateMessage()
	req2 := cloneRequest(req)
	req2.Header.Set("Authorization", "NTLM "+base64Encode(negotiate))

	resp, err = t.Transport.RoundTrip(req2)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusUnauthorized {
		return resp, nil
	}

	// Parse Type 2 (Challenge)
	authHeader = resp.Header.Get("WWW-Authenticate")
	if !strings.HasPrefix(authHeader, "NTLM ") {
		return resp, nil
	}

	challengeB64 := strings.TrimPrefix(authHeader, "NTLM ")
	challenge, err := base64Decode(challengeB64)
	if err != nil {
		return resp, nil
	}
	// Must fully read body to allow connection reuse for NTLM
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	// Parse challenge and build Type 3 (Authenticate)
	challengeMsg, err := ParseChallengeMessage(challenge)
	if err != nil {
		return resp, fmt.Errorf("failed to parse NTLM challenge: %w", err)
	}

	if t.Auth.Debug {
		fmt.Printf("[NTLM] Got challenge, flags: 0x%08x\n", challengeMsg.NegotiateFlags)
		if len(challengeMsg.TargetName) > 0 {
			fmt.Printf("[NTLM] Target: %s\n", fromUnicode(challengeMsg.TargetName))
		}
	}

	authenticate, err := t.Auth.BuildAuthenticateMessage(challengeMsg)
	if err != nil {
		return resp, fmt.Errorf("failed to build authenticate message: %w", err)
	}

	// Final request with authentication
	req3 := cloneRequest(req)
	req3.Header.Set("Authorization", "NTLM "+base64Encode(authenticate))

	resp, err = t.Transport.RoundTrip(req3)
	if t.Auth.Debug && resp != nil {
		fmt.Printf("[NTLM] Final response: HTTP %d\n", resp.StatusCode)
	}
	return resp, err
}

// ChallengeMessage represents NTLM Type 2 message
type ChallengeMessage struct {
	Signature       [8]byte
	MessageType     uint32
	TargetNameLen   uint16
	TargetNameMaxLen uint16
	TargetNameOffset uint32
	NegotiateFlags  uint32
	ServerChallenge [8]byte
	Reserved        [8]byte
	TargetInfoLen   uint16
	TargetInfoMaxLen uint16
	TargetInfoOffset uint32
	Version         [8]byte
	TargetName      []byte
	TargetInfo      []byte
}

// ParseChallengeMessage parses NTLM Type 2 message
func ParseChallengeMessage(data []byte) (*ChallengeMessage, error) {
	if len(data) < 32 {
		return nil, fmt.Errorf("challenge message too short: %d bytes", len(data))
	}

	// Verify signature
	if string(data[:8]) != "NTLMSSP\x00" {
		return nil, fmt.Errorf("invalid NTLM signature")
	}

	msg := &ChallengeMessage{}
	copy(msg.Signature[:], data[:8])
	msg.MessageType = binary.LittleEndian.Uint32(data[8:12])

	if msg.MessageType != 2 {
		return nil, fmt.Errorf("expected Type 2 message, got %d", msg.MessageType)
	}

	msg.TargetNameLen = binary.LittleEndian.Uint16(data[12:14])
	msg.TargetNameMaxLen = binary.LittleEndian.Uint16(data[14:16])
	msg.TargetNameOffset = binary.LittleEndian.Uint32(data[16:20])
	msg.NegotiateFlags = binary.LittleEndian.Uint32(data[20:24])
	copy(msg.ServerChallenge[:], data[24:32])

	// Parse optional fields if present
	if len(data) >= 48 {
		copy(msg.Reserved[:], data[32:40])
		msg.TargetInfoLen = binary.LittleEndian.Uint16(data[40:42])
		msg.TargetInfoMaxLen = binary.LittleEndian.Uint16(data[42:44])
		msg.TargetInfoOffset = binary.LittleEndian.Uint32(data[44:48])
	}

	if len(data) >= 56 {
		copy(msg.Version[:], data[48:56])
	}

	// Extract target name
	if msg.TargetNameLen > 0 && int(msg.TargetNameOffset+uint32(msg.TargetNameLen)) <= len(data) {
		msg.TargetName = data[msg.TargetNameOffset : msg.TargetNameOffset+uint32(msg.TargetNameLen)]
	}

	// Extract target info
	if msg.TargetInfoLen > 0 && int(msg.TargetInfoOffset+uint32(msg.TargetInfoLen)) <= len(data) {
		msg.TargetInfo = data[msg.TargetInfoOffset : msg.TargetInfoOffset+uint32(msg.TargetInfoLen)]
	}

	return msg, nil
}

// BuildNegotiateMessage builds NTLM Type 1 message
func (a *NTLMAuth) BuildNegotiateMessage() []byte {
	flags := uint32(
		NTLMSSP_NEGOTIATE_UNICODE |
			NTLMSSP_NEGOTIATE_OEM |
			NTLMSSP_REQUEST_TARGET |
			NTLMSSP_NEGOTIATE_NTLM |
			NTLMSSP_NEGOTIATE_ALWAYS_SIGN |
			NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY |
			NTLMSSP_NEGOTIATE_TARGET_INFO |
			NTLMSSP_NEGOTIATE_128 |
			NTLMSSP_NEGOTIATE_56,
	)

	msg := bytes.NewBuffer(nil)

	// Signature
	msg.WriteString("NTLMSSP\x00")

	// Message Type (1)
	binary.Write(msg, binary.LittleEndian, uint32(1))

	// Negotiate Flags
	binary.Write(msg, binary.LittleEndian, flags)

	// Domain Name Fields (empty)
	binary.Write(msg, binary.LittleEndian, uint16(0)) // Len
	binary.Write(msg, binary.LittleEndian, uint16(0)) // MaxLen
	binary.Write(msg, binary.LittleEndian, uint32(0)) // Offset

	// Workstation Name Fields (empty)
	binary.Write(msg, binary.LittleEndian, uint16(0)) // Len
	binary.Write(msg, binary.LittleEndian, uint16(0)) // MaxLen
	binary.Write(msg, binary.LittleEndian, uint32(0)) // Offset

	// Version (Windows 10)
	msg.Write([]byte{0x0a, 0x00, 0x63, 0x45, 0x00, 0x00, 0x00, 0x0f})

	return msg.Bytes()
}

// BuildAuthenticateMessage builds NTLM Type 3 message
func (a *NTLMAuth) BuildAuthenticateMessage(challenge *ChallengeMessage) ([]byte, error) {
	// Get NT hash
	var ntHash []byte
	var err error

	if a.Hash != "" {
		// Pass-the-hash: use provided hash
		ntHash, err = hex.DecodeString(a.Hash)
		if err != nil {
			return nil, fmt.Errorf("invalid NT hash hex: %w", err)
		}
		if len(ntHash) != 16 {
			return nil, fmt.Errorf("NT hash must be 16 bytes (32 hex chars)")
		}
	} else {
		// Compute NT hash from password
		ntHash = ComputeNTHash(a.Password)
	}

	// Generate client challenge (8 random bytes)
	clientChallenge := make([]byte, 8)
	if _, err := rand.Read(clientChallenge); err != nil {
		return nil, fmt.Errorf("failed to generate client challenge: %w", err)
	}

	// Get current time as Windows FILETIME
	timestamp := getFileTime()

	// Build NTLMv2 response
	ntlmv2Response, ntProofStr := a.computeNTLMv2Response(
		ntHash,
		challenge.ServerChallenge[:],
		clientChallenge,
		timestamp,
		challenge.TargetInfo,
	)

	// LM response (for NTLMv2, use client challenge padded)
	lmResponse := make([]byte, 24)
	copy(lmResponse, clientChallenge)

	// Compute session base key
	sessionBaseKey := computeHMAC_MD5(ntHash, ntProofStr)
	_ = sessionBaseKey // Used for signing/sealing if needed

	// Build Type 3 message
	return a.buildType3Message(challenge, lmResponse, ntlmv2Response)
}

// computeNTLMv2Response computes the NTLMv2 response
func (a *NTLMAuth) computeNTLMv2Response(
	ntHash []byte,
	serverChallenge []byte,
	clientChallenge []byte,
	timestamp []byte,
	targetInfo []byte,
) ([]byte, []byte) {
	// NTLMv2 hash = HMAC-MD5(NT hash, UPPER(user) + UPPER(domain))
	// Both must be uppercase for NTLMv2
	userDomain := toUnicode(strings.ToUpper(a.User) + strings.ToUpper(a.Domain))
	ntlmv2Hash := computeHMAC_MD5(ntHash, userDomain)

	if a.Debug {
		fmt.Printf("[NTLM] Using domain: %s (uppercase: %s)\n", a.Domain, strings.ToUpper(a.Domain))
	}

	// Build blob (client challenge structure)
	blob := bytes.NewBuffer(nil)
	blob.Write([]byte{0x01, 0x01})     // Resp type, Hi resp type
	blob.Write([]byte{0x00, 0x00})     // Reserved
	blob.Write([]byte{0x00, 0x00, 0x00, 0x00}) // Reserved
	blob.Write(timestamp)               // Time
	blob.Write(clientChallenge)         // Client challenge
	blob.Write([]byte{0x00, 0x00, 0x00, 0x00}) // Reserved
	blob.Write(targetInfo)              // Target info
	blob.Write([]byte{0x00, 0x00, 0x00, 0x00}) // Reserved

	// NTProofStr = HMAC-MD5(NTLMv2 hash, server challenge + blob)
	data := append(serverChallenge, blob.Bytes()...)
	ntProofStr := computeHMAC_MD5(ntlmv2Hash, data)

	// NTLMv2 response = NTProofStr + blob
	response := append(ntProofStr, blob.Bytes()...)

	return response, ntProofStr
}

// buildType3Message builds the NTLM Type 3 authenticate message
func (a *NTLMAuth) buildType3Message(
	challenge *ChallengeMessage,
	lmResponse []byte,
	ntResponse []byte,
) ([]byte, error) {
	flags := challenge.NegotiateFlags

	// Prepare strings as Unicode
	domain := toUnicode(a.Domain)
	user := toUnicode(a.User)
	workstation := toUnicode(a.Workstation)
	if len(workstation) == 0 {
		workstation = toUnicode("WORKSTATION")
	}

	// Calculate offsets
	// Fixed header is 88 bytes (including version)
	offset := uint32(88)

	lmOffset := offset
	offset += uint32(len(lmResponse))

	ntOffset := offset
	offset += uint32(len(ntResponse))

	domainOffset := offset
	offset += uint32(len(domain))

	userOffset := offset
	offset += uint32(len(user))

	workstationOffset := offset
	offset += uint32(len(workstation))

	// Build message
	msg := bytes.NewBuffer(nil)

	// Signature
	msg.WriteString("NTLMSSP\x00")

	// Message Type (3)
	binary.Write(msg, binary.LittleEndian, uint32(3))

	// LM Response
	binary.Write(msg, binary.LittleEndian, uint16(len(lmResponse)))
	binary.Write(msg, binary.LittleEndian, uint16(len(lmResponse)))
	binary.Write(msg, binary.LittleEndian, lmOffset)

	// NT Response
	binary.Write(msg, binary.LittleEndian, uint16(len(ntResponse)))
	binary.Write(msg, binary.LittleEndian, uint16(len(ntResponse)))
	binary.Write(msg, binary.LittleEndian, ntOffset)

	// Domain
	binary.Write(msg, binary.LittleEndian, uint16(len(domain)))
	binary.Write(msg, binary.LittleEndian, uint16(len(domain)))
	binary.Write(msg, binary.LittleEndian, domainOffset)

	// User
	binary.Write(msg, binary.LittleEndian, uint16(len(user)))
	binary.Write(msg, binary.LittleEndian, uint16(len(user)))
	binary.Write(msg, binary.LittleEndian, userOffset)

	// Workstation
	binary.Write(msg, binary.LittleEndian, uint16(len(workstation)))
	binary.Write(msg, binary.LittleEndian, uint16(len(workstation)))
	binary.Write(msg, binary.LittleEndian, workstationOffset)

	// Encrypted Random Session Key (empty for now)
	binary.Write(msg, binary.LittleEndian, uint16(0))
	binary.Write(msg, binary.LittleEndian, uint16(0))
	binary.Write(msg, binary.LittleEndian, offset)

	// Negotiate Flags
	binary.Write(msg, binary.LittleEndian, flags)

	// Version
	msg.Write([]byte{0x0a, 0x00, 0x63, 0x45, 0x00, 0x00, 0x00, 0x0f})

	// MIC (16 bytes of zeros - would be calculated for channel binding)
	msg.Write(make([]byte, 16))

	// Payload
	msg.Write(lmResponse)
	msg.Write(ntResponse)
	msg.Write(domain)
	msg.Write(user)
	msg.Write(workstation)

	return msg.Bytes(), nil
}

// ComputeNTHash computes the NT hash of a password
func ComputeNTHash(password string) []byte {
	// NT Hash = MD4(UTF-16LE(password))
	uni := toUnicode(password)
	hash := md4.New()
	hash.Write(uni)
	return hash.Sum(nil)
}

// computeHMAC_MD5 computes HMAC-MD5
func computeHMAC_MD5(key, data []byte) []byte {
	h := hmac.New(md5.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// toUnicode converts a string to UTF-16LE bytes
func toUnicode(s string) []byte {
	encoded := utf16.Encode([]rune(s))
	result := make([]byte, len(encoded)*2)
	for i, r := range encoded {
		result[i*2] = byte(r)
		result[i*2+1] = byte(r >> 8)
	}
	return result
}

// fromUnicode converts UTF-16LE bytes to a string
func fromUnicode(b []byte) string {
	if len(b)%2 != 0 {
		return string(b)
	}
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = uint16(b[i*2]) | uint16(b[i*2+1])<<8
	}
	return string(utf16.Decode(u16))
}

// getFileTime returns current time as Windows FILETIME (100-nanosecond intervals since 1601)
func getFileTime() []byte {
	// Difference between Unix epoch (1970) and Windows epoch (1601) in 100-nanosecond intervals
	const epochDiff = 116444736000000000

	now := time.Now().UnixNano()/100 + epochDiff

	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, uint64(now))
	return buf
}

// cloneRequest clones an HTTP request
func cloneRequest(req *http.Request) *http.Request {
	clone := req.Clone(req.Context())
	if req.Body != nil && req.GetBody != nil {
		clone.Body, _ = req.GetBody()
	}
	return clone
}

// base64Encode encodes bytes to base64
func base64Encode(data []byte) string {
	const base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

	result := make([]byte, ((len(data)+2)/3)*4)
	for i, j := 0, 0; i < len(data); i, j = i+3, j+4 {
		var val uint32
		val = uint32(data[i]) << 16
		if i+1 < len(data) {
			val |= uint32(data[i+1]) << 8
		}
		if i+2 < len(data) {
			val |= uint32(data[i+2])
		}

		result[j] = base64Chars[(val>>18)&0x3F]
		result[j+1] = base64Chars[(val>>12)&0x3F]

		if i+1 < len(data) {
			result[j+2] = base64Chars[(val>>6)&0x3F]
		} else {
			result[j+2] = '='
		}

		if i+2 < len(data) {
			result[j+3] = base64Chars[val&0x3F]
		} else {
			result[j+3] = '='
		}
	}

	return string(result)
}

// base64Decode decodes base64 to bytes
func base64Decode(s string) ([]byte, error) {
	const base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

	// Remove padding
	s = strings.TrimRight(s, "=")

	// Build decode table
	decodeTable := make([]int, 256)
	for i := range decodeTable {
		decodeTable[i] = -1
	}
	for i, c := range base64Chars {
		decodeTable[c] = i
	}

	result := make([]byte, len(s)*3/4)
	j := 0

	for i := 0; i < len(s); i += 4 {
		var val uint32
		for k := 0; k < 4 && i+k < len(s); k++ {
			idx := decodeTable[s[i+k]]
			if idx < 0 {
				return nil, fmt.Errorf("invalid base64 character")
			}
			val = (val << 6) | uint32(idx)
		}

		// Pad with zeros if we don't have 4 characters
		remaining := len(s) - i
		if remaining < 4 {
			val <<= uint(6 * (4 - remaining))
		}

		if j < len(result) {
			result[j] = byte(val >> 16)
			j++
		}
		if j < len(result) && remaining > 2 {
			result[j] = byte(val >> 8)
			j++
		}
		if j < len(result) && remaining > 3 {
			result[j] = byte(val)
			j++
		}
	}

	return result[:j], nil
}
