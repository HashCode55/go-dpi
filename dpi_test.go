package dpi

import "testing"

func TestReadPCAP(t *testing.T) {
	readPCAP("data/pcap/http.cap")
}

func TestReadPCAPErr(t *testing.T) {
	_, err := readPCAP("data/pcap/nil.cap")
	if err == nil {
		t.Fail()
	}
}

func TestSetFilter(t *testing.T) {
	handle, _ := readPCAP("data/pcap/http.cap")
	var filter = "tcp and port 80"
	setFilter(handle, filter)
}

func TestSetFilterErr(t *testing.T) {
	handle, _ := readPCAP("data/pcap/http.cap")
	var filter = "foobar"
	setFilter(handle, filter)
}

func TestGetPacketChan(t *testing.T) {
	handle, _ := readPCAP("data/pcap/http.cap")
	var i = 0
	for _ = range getPacketChan(handle) {
		i++
	}
	if i != 43 {
		t.Errorf("Expected 43 packages got %d", i)
	}
}

func TestTelnetDetect(t *testing.T) {
	handle, _ := readPCAP("data/pcap/telnet-raw.pcap")
	for packet := range getPacketChan(handle) {
		detectProtocol(packet)
	}
}

func TestHTTPDetect(t *testing.T) {
	handle, _ := readPCAP("data/pcap/http.cap")
	for packet := range getPacketChan(handle) {
		detectProtocol(packet)
	}
}
