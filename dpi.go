package dpi

// Use tcpdump to create a test file
// tcpdump -w test.pcap
// or use the example above for writing pcap files

import (
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// DPI deep packet inspection
type DPI struct {
}

func newDPI() *DPI {
	return new(DPI)
}

func (d *DPI) readPCAP(pcapFile string) (*pcap.Handle, error) {
	// Open file instead of device
	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		return nil, err
	}
	return handle, nil
}

func (d *DPI) setFilter(handle *pcap.Handle, filter string) error {
	err := handle.SetBPFFilter(filter)
	if err != nil {
		return err
	}
	return nil
}

func (d *DPI) getPacketChan(handle *pcap.Handle) chan gopacket.Packet {
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	return packetSource.Packets()
}

func (d *DPI) detectProtocol(packet gopacket.Packet) int {
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {
		// Search for a string inside the payload
		if strings.Contains(string(applicationLayer.Payload()), "HTTP") {
			return 1
		}
	}
	return 0
}

func (d *DPI) detectTelnet(packet gopacket.Packet) int {
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {
		payload := applicationLayer.Payload()
		if len(payload) < 3 {
			return 0
		}
		// https://github.com/ntop/nDPI/blob/61f0eb062ef489cebba21c6c866b47a879d01a24/src/lib/protocols/telnet.c#L53-L56
		if !(payload[0] == 0xff && payload[1] > 0xf9 && payload[1] != 0xff && payload[2] < 0x28) {
			return 0
		}

		for a := 3; a < len(payload)-2; a++ {
			// commands start with a 0xff byte followed by a command byte >= 0xf0 and < 0xff
			// command bytes 0xfb to 0xfe are followed by an option byte <= 0x28
			if !(payload[a] != 0xff || (payload[a] == 0xff && (payload[a+1] >= 0xf0) && (payload[a+1] <= 0xfa)) || (payload[a] == 0xff && (payload[a+1] >= 0xfb) && (payload[a+1] != 0xff) && (payload[a+2] <= 0x28))) {
				return 0
			}
			a++
		}

		return 1
	}
	return 0
}
