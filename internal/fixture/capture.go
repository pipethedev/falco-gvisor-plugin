package fixture

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	captureMagic   = "GVCAP1\n"
	captureLenSize = 4
	maxCaptured    = 4 << 20
)

var errNotCapture = errors.New("not a gvisor capture file")

// WriteCaptureHeader starts a capture of raw remote-sink packets.
func WriteCaptureHeader(w io.Writer) error {
	_, err := io.WriteString(w, captureMagic)
	return err
}

// WriteCapturedPacket appends one packet, prefixed by its little-endian
// 32-bit length.
func WriteCapturedPacket(w io.Writer, pkt []byte) error {
	if err := binary.Write(w, binary.LittleEndian, uint32(len(pkt))); err != nil {
		return err
	}
	_, err := w.Write(pkt)
	return err
}

// ReadCapture returns every packet in a capture written by the recorder.
func ReadCapture(r io.Reader) ([][]byte, error) {
	br := bufio.NewReader(r)
	magic := make([]byte, len(captureMagic))
	if _, err := io.ReadFull(br, magic); err != nil || string(magic) != captureMagic {
		return nil, errNotCapture
	}
	var packets [][]byte
	for {
		var n uint32
		err := binary.Read(br, binary.LittleEndian, &n)
		if errors.Is(err, io.EOF) {
			return packets, nil
		}
		if err != nil {
			return nil, fmt.Errorf("read packet length: %w", err)
		}
		if n > maxCaptured {
			return nil, fmt.Errorf("%w: packet of %d bytes", errNotCapture, n)
		}
		pkt := make([]byte, n)
		if _, err := io.ReadFull(br, pkt); err != nil {
			return nil, fmt.Errorf("read packet: %w", err)
		}
		packets = append(packets, pkt)
	}
}
