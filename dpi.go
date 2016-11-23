package dpi

// Use tcpdump to create a test file
// tcpdump -w test.pcap
// or use the example above for writing pcap files

import (
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func readPCAP(pcapFile string) (*pcap.Handle, error) {
	// Open file instead of device
	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		return nil, err
	}
	return handle, nil
}

func setFilter(handle *pcap.Handle, filter string) error {
	err := handle.SetBPFFilter(filter)
	if err != nil {
		return err
	}
	return nil
}

func getPacketChan(handle *pcap.Handle) chan gopacket.Packet {
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	return packetSource.Packets()
}

func detectProtocol(packet gopacket.Packet) int {
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {
		// Search for a string inside the payload
		if strings.Contains(string(applicationLayer.Payload()), "HTTP") {
			return 1
		}
	}
	return 0
}
