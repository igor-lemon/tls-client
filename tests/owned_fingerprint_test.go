package tests

// Independent owned-peer decoding for the inherited catalogue obligations.
// Input is received TLS bytes, never ClientProfile or clientFingerprints.
// Algorithms: salesforce/ja3 README and FoxIO-LLC/ja4 technical_details/JA4.md.

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"testing"
)

type fingerprintCursor struct {
	data []byte
	err  error
}

func (c *fingerprintCursor) take(n int) []byte {
	if c.err != nil {
		return nil
	}
	if n < 0 || n > len(c.data) {
		c.err = fmt.Errorf("truncated owned ClientHello")
		return nil
	}
	p := c.data[:n]
	c.data = c.data[n:]
	return p
}
func (c *fingerprintCursor) u8() int {
	p := c.take(1)
	if len(p) == 0 {
		return 0
	}
	return int(p[0])
}
func (c *fingerprintCursor) u16() int {
	p := c.take(2)
	if len(p) < 2 {
		return 0
	}
	return int(binary.BigEndian.Uint16(p))
}
func (c *fingerprintCursor) vector8() []byte  { return c.take(c.u8()) }
func (c *fingerprintCursor) vector16() []byte { return c.take(c.u16()) }
func fingerprintGrease(n int) bool            { return n&0x0f0f == 0x0a0a && n>>8 == n&255 }
func fingerprintWords(p []byte) []int {
	var result []int
	for len(p) >= 2 {
		result = append(result, int(binary.BigEndian.Uint16(p)))
		p = p[2:]
	}
	return result
}
func fingerprintNumbers(values []int, base int, grease bool) []string {
	var result []string
	for _, n := range values {
		if grease && fingerprintGrease(n) {
			continue
		}
		if base == 16 {
			result = append(result, fmt.Sprintf("%04x", n))
		} else {
			result = append(result, strconv.Itoa(n))
		}
	}
	return result
}
func fingerprintMD5(s string) string { sum := md5.Sum([]byte(s)); return hex.EncodeToString(sum[:]) }
func fingerprintSHA(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

func ownedHelloFingerprint(records []byte) (map[string]any, error) {
	var handshake []byte
	recordVersion := 0
	for len(records) >= 5 {
		size := int(binary.BigEndian.Uint16(records[3:5]))
		if size > len(records)-5 {
			return nil, fmt.Errorf("cut TLS record")
		}
		if records[0] == 22 {
			if recordVersion == 0 {
				recordVersion = int(binary.BigEndian.Uint16(records[1:3]))
			}
			handshake = append(handshake, records[5:5+size]...)
		}
		records = records[5+size:]
		if len(handshake) >= 4 {
			length := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
			if length > 1<<20 {
				return nil, fmt.Errorf("oversized ClientHello")
			}
			if len(handshake) >= length+4 {
				handshake = handshake[:length+4]
				break
			}
		}
	}
	if len(handshake) < 4 || handshake[0] != 1 {
		return nil, fmt.Errorf("no received ClientHello")
	}
	declared := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
	if declared != len(handshake)-4 {
		return nil, fmt.Errorf("cut ClientHello message")
	}
	cursor := fingerprintCursor{data: handshake[4:]}
	version := cursor.u16()
	random := cursor.take(32)
	session := cursor.vector8()
	cipherBytes := cursor.vector16()
	cursor.vector8()
	var extensionData []byte
	if len(cursor.data) > 0 {
		extensionData = cursor.vector16()
	}
	if cursor.err != nil || len(cursor.data) != 0 || len(cipherBytes)%2 != 0 {
		return nil, fmt.Errorf("invalid ClientHello fields: %v", cursor.err)
	}
	ciphers := fingerprintWords(cipherBytes)
	extensions := fingerprintCursor{data: extensionData}
	var ids, groups, points, signatures, versions []int
	var rows []map[string]any
	firstALPN := ""
	sni := false
	for len(extensions.data) > 0 && extensions.err == nil {
		id := extensions.u16()
		data := extensions.vector16()
		ids = append(ids, id)
		row := map[string]any{"name": fmt.Sprintf("extension (%d)", id), "data": hex.EncodeToString(data)}
		value := fingerprintCursor{data: data}
		switch id {
		case 0:
			sni = true
		case 10:
			p := value.vector16()
			groups = fingerprintWords(p)
			if len(p)%2 != 0 {
				return nil, fmt.Errorf("odd supported groups")
			}
		case 11:
			for _, n := range value.vector8() {
				points = append(points, int(n))
			}
		case 13:
			p := value.vector16()
			if len(p)%2 != 0 {
				return nil, fmt.Errorf("odd signature algorithms")
			}
			signatures = fingerprintWords(p)
			row["name"] = "signature_algorithms (13)"
			var labels []string
			for _, n := range signatures {
				labels = append(labels, fmt.Sprintf("0x%04x", n))
			}
			row["signature_algorithms"] = labels
		case 16:
			names := fingerprintCursor{data: value.vector16()}
			var protocols []string
			for len(names.data) > 0 && names.err == nil {
				protocols = append(protocols, string(names.vector8()))
			}
			if names.err != nil {
				return nil, names.err
			}
			if len(protocols) > 0 {
				firstALPN = protocols[0]
			}
			row["protocols"] = protocols
		case 43:
			p := value.vector8()
			if len(p)%2 != 0 {
				return nil, fmt.Errorf("odd supported versions")
			}
			versions = fingerprintWords(p)
		default:
			value.data = nil
		}
		if value.err != nil {
			return nil, value.err
		}
		rows = append(rows, row)
	}
	if extensions.err != nil {
		return nil, extensions.err
	}
	ja3 := strconv.Itoa(version) + "," + strings.Join(fingerprintNumbers(ciphers, 10, true), "-") + "," + strings.Join(fingerprintNumbers(ids, 10, true), "-") + "," + strings.Join(fingerprintNumbers(groups, 10, true), "-") + "," + strings.Join(fingerprintNumbers(points, 10, false), "-")
	if len(versions) == 0 {
		versions = []int{version}
	}
	highest := 0
	for _, v := range versions {
		if !fingerprintGrease(v) && v > highest {
			highest = v
		}
	}
	versionLabel := map[int]string{0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3", 2: "s2"}[highest]
	if versionLabel == "" {
		versionLabel = "00"
	}
	alpn := "00"
	if len(firstALPN) > 0 {
		ascii := func(c byte) bool { return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }
		if ascii(firstALPN[0]) && ascii(firstALPN[len(firstALPN)-1]) {
			alpn = string([]byte{firstALPN[0], firstALPN[len(firstALPN)-1]})
		} else {
			p := hex.EncodeToString([]byte(firstALPN))
			alpn = string([]byte{p[0], p[len(p)-1]})
		}
	}
	cipherHex := fingerprintNumbers(ciphers, 16, true)
	sort.Strings(cipherHex)
	extensionHex := fingerprintNumbers(ids, 16, true)
	count := len(extensionHex)
	var hashedExtensions []string
	for _, id := range extensionHex {
		if id != "0000" && id != "0010" {
			hashedExtensions = append(hashedExtensions, id)
		}
	}
	sort.Strings(hashedExtensions)
	suffix := strings.Join(hashedExtensions, ",")
	sigHex := fingerprintNumbers(signatures, 16, true)
	if len(sigHex) > 0 {
		suffix += "_" + strings.Join(sigHex, ",")
	}
	domain := "i"
	if sni {
		domain = "d"
	}
	prefix := fmt.Sprintf("t%s%s%02d%02d%s", versionLabel, domain, min(len(cipherHex), 99), min(count, 99), alpn)
	cipherHash, extensionHash := "000000000000", "000000000000"
	if len(cipherHex) > 0 {
		cipherHash = fingerprintSHA(strings.Join(cipherHex, ","))
	}
	if len(hashedExtensions) > 0 {
		extensionHash = fingerprintSHA(suffix)
	}
	return map[string]any{"ja3": ja3, "ja3_hash": fingerprintMD5(ja3), "ja4": prefix + "_" + cipherHash + "_" + extensionHash, "ja4_r": prefix + "_" + strings.Join(cipherHex, ",") + "_" + suffix, "client_random": hex.EncodeToString(random), "session_id": hex.EncodeToString(session), "extensions": rows, "tls_version_record": fmt.Sprintf("0x%04x", recordVersion)}, nil
}

// Published Salesforce JA3 worked example, assembled independently of profiles.
func ownedExampleHello() []byte {
	words := func(values ...int) []byte {
		var p []byte
		for _, v := range values {
			p = append(p, byte(v>>8), byte(v))
		}
		return p
	}
	vec := func(p []byte) []byte { return append(words(len(p)), p...) }
	ciphers := words(47, 53, 5, 10, 49161, 49162, 49171, 49172, 50, 56, 19, 4)
	var exts []byte
	for _, ext := range []struct {
		id   int
		data []byte
	}{{0, []byte{0, 4, 0, 0, 1, 'a'}}, {10, vec(words(23, 24, 25))}, {11, []byte{1, 0}}} {
		exts = append(exts, words(ext.id)...)
		exts = append(exts, vec(ext.data)...)
	}
	body := append(words(769), make([]byte, 32)...)
	body = append(body, 0)
	body = append(body, vec(ciphers)...)
	body = append(body, 1, 0)
	body = append(body, vec(exts)...)
	hello := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	return append([]byte{22, 3, 1, byte(len(hello) >> 8), byte(len(hello))}, hello...)
}

func TestOwnedFingerprintKnownAnswerAndNegativeControls(t *testing.T) {
	record := ownedExampleHello()
	result, err := ownedHelloFingerprint(record)
	if err != nil {
		t.Fatal(err)
	}
	if result["ja3"] != "769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0" || result["ja3_hash"] != "ada70206e40642a3e4461f35503241d5" {
		t.Fatalf("known answer=%v", result["ja3"])
	}
	changed := append([]byte(nil), record...)
	changed[46] ^= 1
	alternate, err := ownedHelloFingerprint(changed)
	if err != nil {
		t.Fatal(err)
	}
	if alternate["ja3_hash"] == result["ja3_hash"] {
		t.Fatal("cipher-byte mutation did not change fingerprint")
	}
	for _, cut := range []int{0, 4, 10, len(record) - 1} {
		if _, err := ownedHelloFingerprint(record[:cut]); err == nil {
			t.Fatalf("accepted truncated record %d", cut)
		}
	}
}

// FoxIO's published worked example, including original extension/signature
// ordering. A changed GREASE draw must not affect JA4, but real fields must.
func TestOwnedJA4PublishedExample(t *testing.T) {
	words := func(v ...int) []byte {
		var p []byte
		for _, n := range v {
			p = append(p, byte(n>>8), byte(n))
		}
		return p
	}
	vec := func(p []byte) []byte { return append(words(len(p)), p...) }
	ciphers := words(0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035)
	ids := []int{0x001b, 0, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d, 0x0005, 0x0023, 0x0012, 0x002b, 0xff01, 0x000b, 0x000a, 0x0015}
	var extensions []byte
	for _, id := range ids {
		var payload []byte
		switch id {
		case 0:
			payload = []byte{0, 4, 0, 0, 1, 'a'}
		case 10:
			payload = vec(words(29, 23, 24))
		case 11:
			payload = []byte{1, 0}
		case 13:
			payload = vec(words(0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601))
		case 16:
			payload = []byte{0, 3, 2, 'h', '2'}
		case 43:
			payload = []byte{2, 3, 4}
		}
		extensions = append(extensions, words(id)...)
		extensions = append(extensions, vec(payload)...)
	}
	body := append(words(0x0303), make([]byte, 32)...)
	body = append(body, 0)
	body = append(body, vec(ciphers)...)
	body = append(body, 1, 0)
	body = append(body, vec(extensions)...)
	message := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	wire := append([]byte{22, 3, 1, byte(len(message) >> 8), byte(len(message))}, message...)
	got, err := ownedHelloFingerprint(wire)
	if err != nil {
		t.Fatal(err)
	}
	if got["ja4"] != "t13d1516h2_8daaf6152771_e5627efa2ab1" {
		t.Fatalf("published JA4 example=%v", got["ja4"])
	}
}
