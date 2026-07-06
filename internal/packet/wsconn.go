// WebSocket (RFC 6455) carrier for the TCP transport. A wsConn is a net.Conn that
// presents a plain byte STREAM to the caller while framing every write as a binary
// WebSocket frame and de-framing reads — so the existing connFramer (length-prefix
// + AEAD) rides on top unchanged, exactly as it does over a raw TCP or a TLS-cover
// conn. The point of the WebSocket carrier is CDN-frontability: a client can reach
// a CDN edge over wss:// with the Host/SNI of an allowed domain, and the CDN proxies
// the WebSocket to our origin — the censor sees TLS to the CDN (collateral freedom),
// not a tunnel. Frame masking follows the RFC: the client masks, the server does not.
package packet

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// wsGUID is the RFC 6455 magic value mixed into Sec-WebSocket-Accept.
const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

var errNotWS = errors.New("ws: not a websocket upgrade")

// wsConn wraps a stream conn with WebSocket binary framing, presenting a byte
// stream. r is the buffered reader that already consumed the HTTP handshake, so
// any bytes read past it (an eager first frame) are not lost.
type wsConn struct {
	net.Conn
	r      *bufio.Reader
	client bool   // clients MUST mask outbound frames (RFC 6455 §5.3)
	rbuf   []byte // leftover payload from the current inbound frame
	wmu    sync.Mutex
}

// Read returns de-framed payload bytes as a stream. WebSocket control frames are
// handled transparently: a ping is answered with a pong, a pong is ignored, a close
// ends the stream. Data opcodes (binary/text/continuation) carry our bytes.
func (c *wsConn) Read(p []byte) (int, error) {
	for len(c.rbuf) == 0 {
		payload, opcode, err := readWSFrame(c.r)
		if err != nil {
			return 0, err
		}
		switch opcode {
		case 0x0, 0x1, 0x2: // continuation / text / binary — data
			c.rbuf = payload
		case 0x8: // close
			return 0, io.EOF
		case 0x9: // ping -> pong
			_ = c.writeWSFrame(0xA, payload)
		case 0xA: // pong — ignore
		}
	}
	n := copy(p, c.rbuf)
	c.rbuf = c.rbuf[n:]
	return n, nil
}

// Write sends p as a single binary WebSocket frame.
func (c *wsConn) Write(p []byte) (int, error) {
	if err := c.writeWSFrame(0x2, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// writeWSFrame emits one WebSocket frame (FIN set). The write lock keeps a control
// pong (sent from Read) from interleaving bytes with a data frame.
func (c *wsConn) writeWSFrame(opcode byte, payload []byte) error {
	n := len(payload)
	hdr := make([]byte, 0, 14)
	hdr = append(hdr, 0x80|opcode) // FIN + opcode
	var maskBit byte
	if c.client {
		maskBit = 0x80
	}
	switch {
	case n < 126:
		hdr = append(hdr, maskBit|byte(n))
	case n < 65536:
		hdr = append(hdr, maskBit|126, byte(n>>8), byte(n))
	default:
		hdr = append(hdr, maskBit|127)
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(n))
		hdr = append(hdr, ext[:]...)
	}
	body := payload
	if c.client {
		var key [4]byte
		if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
			return err
		}
		hdr = append(hdr, key[:]...)
		body = make([]byte, n)
		for i := 0; i < n; i++ {
			body[i] = payload[i] ^ key[i&3]
		}
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	c.Conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	if _, err := c.Conn.Write(hdr); err != nil {
		return err
	}
	_, err := c.Conn.Write(body)
	return err
}

// readWSFrame reads a single WebSocket frame and returns its payload and opcode.
// Server-received frames must be masked (RFC 6455 §5.1); we unmask them. Frame
// size is bounded so a peer cannot force a huge allocation.
func readWSFrame(r *bufio.Reader) (payload []byte, opcode byte, err error) {
	var h [2]byte
	if _, err = io.ReadFull(r, h[:]); err != nil {
		return nil, 0, err
	}
	opcode = h[0] & 0x0f
	masked := h[1]&0x80 != 0
	n := int(h[1] & 0x7f)
	switch n {
	case 126:
		var e [2]byte
		if _, err = io.ReadFull(r, e[:]); err != nil {
			return nil, 0, err
		}
		n = int(binary.BigEndian.Uint16(e[:]))
	case 127:
		var e [8]byte
		if _, err = io.ReadFull(r, e[:]); err != nil {
			return nil, 0, err
		}
		n = int(binary.BigEndian.Uint64(e[:]))
	}
	if n < 0 || n > maxFrame*2 {
		return nil, 0, errDesync
	}
	var mask [4]byte
	if masked {
		if _, err = io.ReadFull(r, mask[:]); err != nil {
			return nil, 0, err
		}
	}
	buf := make([]byte, n)
	if _, err = io.ReadFull(r, buf); err != nil {
		return nil, 0, err
	}
	if masked {
		for i := 0; i < n; i++ {
			buf[i] ^= mask[i&3]
		}
	}
	return buf, opcode, nil
}

// wsAccept computes the Sec-WebSocket-Accept value for a client key.
func wsAccept(key string) string {
	h := sha1.Sum([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(h[:])
}

// wsClientHandshake performs the HTTP Upgrade against host/path and returns the
// buffered reader (holding any post-handshake bytes) for the wsConn to frame from.
func wsClientHandshake(conn net.Conn, host, path string, deadline time.Time) (*bufio.Reader, error) {
	if path == "" {
		path = "/"
	}
	var kb [16]byte
	if _, err := io.ReadFull(rand.Reader, kb[:]); err != nil {
		return nil, err
	}
	key := base64.StdEncoding.EncodeToString(kb[:])
	req := "GET " + path + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
	conn.SetDeadline(deadline)
	if _, err := conn.Write([]byte(req)); err != nil {
		return nil, err
	}
	r := bufio.NewReaderSize(conn, readBufSize)
	resp, err := http.ReadResponse(r, &http.Request{Method: "GET"})
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols ||
		!strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") ||
		resp.Header.Get("Sec-WebSocket-Accept") != wsAccept(key) {
		return nil, errNotWS
	}
	var zero time.Time
	conn.SetDeadline(zero) // clear; the framer sets its own per-frame deadlines
	return r, nil
}

// wsServerHandshake reads the HTTP request and, if it is a WebSocket upgrade,
// answers 101 and returns the buffered reader for framing. A non-WS request (a
// probe, a scanner, a browser) gets a plausible 404 and errNotWS, so the port
// looks like an ordinary idle web endpoint rather than a tunnel.
func wsServerHandshake(conn net.Conn, deadline time.Time) (*bufio.Reader, error) {
	conn.SetDeadline(deadline)
	r := bufio.NewReaderSize(conn, readBufSize)
	req, err := http.ReadRequest(r)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
		_, _ = conn.Write([]byte("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
		return nil, errNotWS
	}
	accept := wsAccept(req.Header.Get("Sec-WebSocket-Key"))
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
	if _, err := conn.Write([]byte(resp)); err != nil {
		return nil, err
	}
	var zero time.Time
	conn.SetDeadline(zero)
	return r, nil
}
