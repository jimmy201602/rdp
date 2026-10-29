package nla

import (
	"bytes"
	"errors"
)

// SPNEGO (RFC 4178) wrapping of NTLM, as sent by mstsc and by FreeRDP when
// Kerberos is compiled in. Only the NTLM mechanism is accepted.

var (
	oidSPNEGO = []byte{0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}
	oidNTLM   = []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a}
)

const (
	negAcceptCompleted  = 0
	negAcceptIncomplete = 1
	negReject           = 2
	negRequestMIC       = 3
	negStateAbsent      = -1
)

const (
	tagOID         byte = 0x06
	tagOctetString byte = 0x04
	tagEnumerated  byte = 0x0a
	tagSequence    byte = 0x30
	tagApplication byte = 0x60
	tagContext0    byte = 0xa0
)

func derTLV(tag byte, content []byte) []byte {
	n := len(content)
	var hdr []byte
	switch {
	case n < 0x80:
		hdr = []byte{tag, byte(n)}
	case n < 0x100:
		hdr = []byte{tag, 0x81, byte(n)}
	case n < 0x10000:
		hdr = []byte{tag, 0x82, byte(n >> 8), byte(n)}
	default:
		hdr = []byte{tag, 0x83, byte(n >> 16), byte(n >> 8), byte(n)}
	}
	return append(hdr, content...)
}

func derRead(p []byte) (tag byte, content, rest []byte, err error) {
	if len(p) < 2 {
		return 0, nil, nil, errors.New("short DER element")
	}
	tag = p[0]
	n := int(p[1])
	p = p[2:]
	if n&0x80 != 0 {
		count := n & 0x7f
		if count == 0 || count > 3 || len(p) < count {
			return 0, nil, nil, errors.New("invalid DER length")
		}
		n = 0
		for _, b := range p[:count] {
			n = n<<8 | int(b)
		}
		p = p[count:]
	}
	if n > len(p) {
		return 0, nil, nil, errors.New("DER element exceeds buffer")
	}
	return tag, p[:n], p[n:], nil
}

func derExpect(p []byte, want byte) ([]byte, []byte, error) {
	tag, content, rest, err := derRead(p)
	if err != nil {
		return nil, nil, err
	}
	if tag != want {
		return nil, nil, errors.New("unexpected DER tag")
	}
	return content, rest, nil
}

func isSPNEGO(token []byte) bool {
	return len(token) > 0 && (token[0] == tagApplication || token[0] == tagContext0+1)
}

type negTokenInit struct {
	mechTypes []byte   // DER MechTypeList including its SEQUENCE tag (signed by the MIC)
	mechs     [][]byte // OID contents in preference order
	mechToken []byte
}

// parseNegTokenInit decodes InitialContextToken { spnego OID, [0] NegTokenInit }.
func parseNegTokenInit(p []byte) (*negTokenInit, error) {
	body, rest, err := derExpect(p, tagApplication)
	if err != nil || len(rest) != 0 {
		return nil, errors.New("invalid SPNEGO initial token")
	}
	oid, body, err := derExpect(body, tagOID)
	if err != nil || !bytes.Equal(oid, oidSPNEGO) {
		return nil, errors.New("initial token is not SPNEGO")
	}
	inner, rest, err := derExpect(body, tagContext0)
	if err != nil || len(rest) != 0 {
		return nil, errors.New("invalid NegTokenInit")
	}
	seq, rest, err := derExpect(inner, tagSequence)
	if err != nil || len(rest) != 0 {
		return nil, errors.New("invalid NegTokenInit")
	}
	t := &negTokenInit{}
	for len(seq) > 0 {
		tag, content, next, err := derRead(seq)
		if err != nil {
			return nil, err
		}
		switch tag {
		case tagContext0:
			list, rest, err := derExpect(content, tagSequence)
			if err != nil || len(rest) != 0 {
				return nil, errors.New("invalid SPNEGO mechTypes")
			}
			t.mechTypes = content
			for len(list) > 0 {
				oid, more, err := derExpect(list, tagOID)
				if err != nil {
					return nil, err
				}
				t.mechs = append(t.mechs, oid)
				list = more
			}
		case tagContext0 + 2:
			if t.mechToken, _, err = derExpect(content, tagOctetString); err != nil {
				return nil, err
			}
		case tagContext0 + 1, tagContext0 + 3: // reqFlags, mechListMIC: ignored on the first leg
		default:
			return nil, errors.New("unexpected NegTokenInit field")
		}
		seq = next
	}
	if len(t.mechs) == 0 {
		return nil, errors.New("SPNEGO token without mechTypes")
	}
	return t, nil
}

type negTokenResp struct {
	negState      int
	supportedMech []byte
	responseToken []byte
	mic           []byte
}

func (r negTokenResp) encode() []byte {
	var seq []byte
	if r.negState != negStateAbsent {
		seq = append(seq, derTLV(tagContext0, derTLV(tagEnumerated, []byte{byte(r.negState)}))...)
	}
	if len(r.supportedMech) > 0 {
		seq = append(seq, derTLV(tagContext0+1, derTLV(tagOID, r.supportedMech))...)
	}
	if len(r.responseToken) > 0 {
		seq = append(seq, derTLV(tagContext0+2, derTLV(tagOctetString, r.responseToken))...)
	}
	if len(r.mic) > 0 {
		seq = append(seq, derTLV(tagContext0+3, derTLV(tagOctetString, r.mic))...)
	}
	return derTLV(tagContext0+1, derTLV(tagSequence, seq))
}

// parseNegTokenResp decodes [1] NegTokenResp.
func parseNegTokenResp(p []byte) (*negTokenResp, error) {
	inner, rest, err := derExpect(p, tagContext0+1)
	if err != nil || len(rest) != 0 {
		return nil, errors.New("invalid NegTokenResp")
	}
	seq, rest, err := derExpect(inner, tagSequence)
	if err != nil || len(rest) != 0 {
		return nil, errors.New("invalid NegTokenResp")
	}
	r := &negTokenResp{negState: negStateAbsent}
	for len(seq) > 0 {
		tag, content, next, err := derRead(seq)
		if err != nil {
			return nil, err
		}
		switch tag {
		case tagContext0:
			v, _, err := derExpect(content, tagEnumerated)
			if err != nil || len(v) != 1 {
				return nil, errors.New("invalid SPNEGO negState")
			}
			r.negState = int(v[0])
		case tagContext0 + 1:
			if r.supportedMech, _, err = derExpect(content, tagOID); err != nil {
				return nil, err
			}
		case tagContext0 + 2:
			if r.responseToken, _, err = derExpect(content, tagOctetString); err != nil {
				return nil, err
			}
		case tagContext0 + 3:
			if r.mic, _, err = derExpect(content, tagOctetString); err != nil {
				return nil, err
			}
		default:
			return nil, errors.New("unexpected NegTokenResp field")
		}
		seq = next
	}
	return r, nil
}

// acceptor runs the server side of the authentication token exchange, with
// or without SPNEGO framing, and ends with verified session security.
type acceptor struct {
	cfg       ServerConfig
	spnego    bool
	micNeeded bool
	mechTypes []byte
	st        *challengeState
	stage     int
	result    *verified
	password  string // the looked-up password, compared with the delegated one
}

func (a *acceptor) lookup(user, domain string) (string, bool) {
	password, ok := a.cfg.Lookup(user, domain)
	if ok {
		a.password = password
	}
	return password, ok
}

func (a *acceptor) challenge(negotiate []byte) ([]byte, error) {
	st, err := ntlmChallenge(negotiate, a.cfg.DomainName, a.cfg.ComputerName, a.cfg.Now())
	if err != nil {
		return nil, err
	}
	a.st = st
	a.stage = 2
	return st.challenge, nil
}

// step consumes one client token and returns the reply token (nil for
// none) and whether the client is now authenticated.
func (a *acceptor) step(token []byte) ([]byte, bool, error) {
	switch a.stage {
	case 0:
		if !isSPNEGO(token) {
			out, err := a.challenge(token)
			return out, false, err
		}
		init, err := parseNegTokenInit(token)
		if err != nil {
			return nil, false, err
		}
		a.spnego, a.mechTypes = true, init.mechTypes
		haveNTLM := false
		for _, m := range init.mechs {
			haveNTLM = haveNTLM || bytes.Equal(m, oidNTLM)
		}
		if !haveNTLM {
			return nil, false, errors.New("client offers no NTLM mechanism")
		}
		if bytes.Equal(init.mechs[0], oidNTLM) && len(init.mechToken) > 0 {
			out, err := a.challenge(init.mechToken)
			if err != nil {
				return nil, false, err
			}
			return negTokenResp{negState: negAcceptIncomplete, supportedMech: oidNTLM, responseToken: out}.encode(), false, nil
		}
		// The optimistic token was for another mechanism: ask for NTLM
		// and, as the preference changed, for a mechListMIC.
		a.micNeeded, a.stage = true, 1
		return negTokenResp{negState: negRequestMIC, supportedMech: oidNTLM}.encode(), false, nil
	case 1:
		resp, err := parseNegTokenResp(token)
		if err != nil {
			return nil, false, err
		}
		out, err := a.challenge(resp.responseToken)
		if err != nil {
			return nil, false, err
		}
		return negTokenResp{negState: negAcceptIncomplete, responseToken: out}.encode(), false, nil
	case 2:
		var mic []byte
		clientState := negStateAbsent
		if a.spnego {
			resp, err := parseNegTokenResp(token)
			if err != nil {
				return nil, false, err
			}
			token, mic, clientState = resp.responseToken, resp.mic, resp.negState
		}
		v, err := a.st.verify(token, a.cfg.Binding, a.lookup)
		if err != nil {
			return nil, false, err
		}
		a.result, a.stage = v, 3
		if !a.spnego {
			return nil, true, nil
		}
		if len(mic) == 0 {
			if a.micNeeded {
				return nil, false, errors.New("SPNEGO mechListMIC required but missing")
			}
			return negTokenResp{negState: negAcceptCompleted}.encode(), true, nil
		}
		if err := v.security.client.verify(a.mechTypes, mic); err != nil {
			return nil, false, err
		}
		out := negTokenResp{negState: negAcceptCompleted}
		if clientState != negAcceptCompleted {
			out.mic = v.security.server.signature(a.mechTypes)
		}
		if err := v.security.resetCiphers(); err != nil {
			return nil, false, err
		}
		return out.encode(), true, nil
	}
	return nil, false, errors.New("unexpected authentication token")
}
