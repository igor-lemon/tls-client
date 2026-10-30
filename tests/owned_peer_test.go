package tests

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"crypto/tls"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type ownedHelloConn struct {
	net.Conn
	hello []byte
}

func (c *ownedHelloConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if len(c.hello) < 1<<20 {
		keep := min(n, (1<<20)-len(c.hello))
		c.hello = append(c.hello, p[:keep]...)
	}
	return n, err
}

// newOwnedFingerprintPeer exposes only this test's loopback listener. There is
// no profile argument: all returned fingerprints come from received bytes.
func newOwnedFingerprintPeer(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	config := &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t)}, NextProtos: []string{"h2", "http/1.1"}}
	var mu sync.Mutex
	connections := make(map[net.Conn]struct{})
	var serving sync.WaitGroup
	accepted := make(chan struct{})
	go func() {
		defer close(accepted)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			connections[conn] = struct{}{}
			mu.Unlock()
			serving.Add(1)
			go func() {
				defer serving.Done()
				defer conn.Close()
				defer func() { mu.Lock(); delete(connections, conn); mu.Unlock() }()
				conn.SetDeadline(time.Now().Add(30 * time.Second))
				observed := &ownedHelloConn{Conn: conn}
				secure := tls.Server(observed, config)
				if err := secure.Handshake(); err != nil {
					return
				}
				hello, err := ownedHelloFingerprint(observed.hello)
				if err != nil {
					t.Errorf("owned ClientHello decode: %v", err)
					return
				}
				hello["tls_version_negotiated"] = fmt.Sprintf("0x%04x", secure.ConnectionState().Version)
				hello["did_resume"] = secure.ConnectionState().DidResume
				if secure.ConnectionState().NegotiatedProtocol == "h2" {
					_ = serveOwnedH2(secure, hello)
				} else {
					_ = serveOwnedH1(secure, hello)
				}
			}()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		<-accepted
		mu.Lock()
		var active []net.Conn
		for conn := range connections {
			active = append(active, conn)
		}
		mu.Unlock()
		for _, conn := range active {
			conn.Close()
		}
		done := make(chan struct{})
		go func() { serving.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("owned fingerprint peer did not release connections")
		}
	})
	return "https://" + listener.Addr().String() + "/api/all"
}

func serveOwnedH1(conn io.ReadWriter, hello map[string]any) error {
	reader := bufio.NewReader(conn)
	for {
		first, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		parts := strings.Fields(first)
		if len(parts) != 3 {
			return fmt.Errorf("invalid request line")
		}
		var headers []string
		length := 0
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return err
			}
			line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
			if line == "" {
				break
			}
			headers = append(headers, line)
			key, value, ok := strings.Cut(line, ":")
			if !ok {
				return fmt.Errorf("invalid field")
			}
			if strings.EqualFold(key, "Content-Length") {
				n, err := strconv.Atoi(strings.TrimSpace(value))
				if err != nil || n < 0 || n > 1<<20 {
					return fmt.Errorf("invalid owned body length")
				}
				length = n
			}
			if strings.EqualFold(key, "Transfer-Encoding") {
				return fmt.Errorf("owned fingerprint H1 fixture requires a fixed body length")
			}
		}
		if _, err := io.CopyN(io.Discard, reader, int64(length)); err != nil {
			return err
		}
		body, err := json.Marshal(map[string]any{"tls": hello, "http_version": "HTTP/1.1", "method": parts[0], "http1": map[string]any{"headers": headers}})
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n", len(body)); err != nil {
			return err
		}
		if _, err := conn.Write(body); err != nil {
			return err
		}
	}
}

type ownedH2Request struct {
	fields []hpack.HeaderField
	body   int
}

func serveOwnedH2(conn io.ReadWriter, hello map[string]any) error {
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(conn, preface); err != nil {
		return err
	}
	if string(preface) != http2.ClientPreface {
		return fmt.Errorf("invalid H2 preface")
	}
	framer := http2.NewFramer(conn, conn)
	decoder := hpack.NewDecoder(4096, nil)
	var frames []map[string]any
	settings, update := "", "00"
	settingsSeen, replied := false, false
	var priorities []string
	requests := make(map[uint32]*ownedH2Request)
	respond := func(id uint32) error {
		request := requests[id]
		if request == nil {
			return fmt.Errorf("DATA without headers")
		}
		var pseudo []string
		method := ""
		for _, field := range request.fields {
			if strings.HasPrefix(field.Name, ":") {
				code := map[string]string{":method": "m", ":authority": "a", ":scheme": "s", ":path": "p"}[field.Name]
				if code == "" {
					return fmt.Errorf("unknown pseudo-header")
				}
				pseudo = append(pseudo, code)
			}
			if field.Name == ":method" {
				method = field.Value
			}
		}
		priority := "0"
		if len(priorities) > 0 {
			priority = strings.Join(priorities, ",")
		}
		fingerprint := settings + "|" + update + "|" + priority + "|" + strings.Join(pseudo, ",")
		body, err := json.Marshal(map[string]any{"tls": hello, "http_version": "h2", "method": method, "http2": map[string]any{"sent_frames": frames, "akamai_fingerprint": fingerprint, "akamai_fingerprint_hash": fingerprintMD5(fingerprint)}})
		if err != nil {
			return err
		}
		var block bytes.Buffer
		encoder := hpack.NewEncoder(&block)
		for _, field := range []hpack.HeaderField{{Name: ":status", Value: "200"}, {Name: "content-type", Value: "application/json"}, {Name: "content-length", Value: strconv.Itoa(len(body))}} {
			if err := encoder.WriteField(field); err != nil {
				return err
			}
		}
		if err := framer.WriteHeaders(http2.HeadersFrameParam{StreamID: id, EndHeaders: true, BlockFragment: block.Bytes()}); err != nil {
			return err
		}
		for len(body) > 0 {
			size := min(len(body), 16384)
			if err := framer.WriteData(id, size == len(body), body[:size]); err != nil {
				return err
			}
			body = body[size:]
		}
		delete(requests, id)
		return nil
	}
	for {
		frame, err := framer.ReadFrame()
		if err != nil {
			return err
		}
		switch f := frame.(type) {
		case *http2.SettingsFrame:
			entry := map[string]any{"frame_type": "SETTINGS", "stream_id": 0}
			if f.IsAck() {
				entry["flags"] = []string{"ACK"}
			} else {
				var raw []string
				f.ForeachSetting(func(s http2.Setting) error { raw = append(raw, fmt.Sprintf("%d:%d", s.ID, s.Val)); return nil })
				entry["settings"] = raw
				if !settingsSeen {
					settings = strings.Join(raw, ";")
					settingsSeen = true
				}
				if replied {
					if err := framer.WriteSettingsAck(); err != nil {
						return err
					}
				}
			}
			frames = append(frames, entry)
		case *http2.WindowUpdateFrame:
			frames = append(frames, map[string]any{"frame_type": "WINDOW_UPDATE", "stream_id": f.StreamID, "increment": f.Increment})
			if f.StreamID == 0 && update == "00" {
				update = strconv.FormatUint(uint64(f.Increment), 10)
			}
		case *http2.PriorityFrame:
			exclusive := 0
			if f.Exclusive {
				exclusive = 1
			}
			priorities = append(priorities, fmt.Sprintf("%d:%d:%d:%d", f.StreamID, exclusive, f.StreamDep, int(f.Weight)+1))
			frames = append(frames, map[string]any{"frame_type": "PRIORITY", "stream_id": f.StreamID, "priority": map[string]any{"weight": int(f.Weight) + 1, "depends_on": f.StreamDep, "exclusive": exclusive}})
		case *http2.HeadersFrame:
			fragment := append([]byte(nil), f.HeaderBlockFragment()...)
			ended := f.HeadersEnded()
			for !ended {
				next, err := framer.ReadFrame()
				if err != nil {
					return err
				}
				part, ok := next.(*http2.ContinuationFrame)
				if !ok || part.StreamID != f.StreamID {
					return fmt.Errorf("invalid continuation")
				}
				fragment = append(fragment, part.HeaderBlockFragment()...)
				if len(fragment) > 1<<20 {
					return fmt.Errorf("owned header block too large")
				}
				ended = part.HeadersEnded()
			}
			fields, err := decoder.DecodeFull(fragment)
			if err != nil {
				return err
			}
			var headers []string
			for _, field := range fields {
				headers = append(headers, field.Name+": "+field.Value)
			}
			frames = append(frames, map[string]any{"frame_type": "HEADERS", "stream_id": f.StreamID, "headers": headers})
			requests[f.StreamID] = &ownedH2Request{fields: fields}
			// A passive first cohort preserves every actual preface frame and does
			// not insert a SETTINGS ACK into the request's original flight.
			if !replied {
				if err := framer.WriteSettings(); err != nil {
					return err
				}
				if settingsSeen {
					if err := framer.WriteSettingsAck(); err != nil {
						return err
					}
				}
				replied = true
			}
			if f.StreamEnded() {
				if err := respond(f.StreamID); err != nil {
					return err
				}
			}
		case *http2.DataFrame:
			request := requests[f.StreamID]
			if request == nil {
				return fmt.Errorf("DATA without headers")
			}
			request.body += len(f.Data())
			if request.body > 1<<20 {
				return fmt.Errorf("owned body too large")
			}
			frames = append(frames, map[string]any{"frame_type": "DATA", "stream_id": f.StreamID, "length": len(f.Data())})
			if f.StreamEnded() {
				if err := respond(f.StreamID); err != nil {
					return err
				}
			}
		case *http2.PingFrame:
			frames = append(frames, map[string]any{"frame_type": "PING"})
			if !f.IsAck() {
				if err := framer.WritePing(true, f.Data); err != nil {
					return err
				}
			}
		case *http2.GoAwayFrame:
			return nil
		case *http2.RSTStreamFrame:
			delete(requests, f.StreamID)
		default:
			return fmt.Errorf("unexpected owned frame %T", f)
		}
	}
}
