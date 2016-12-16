package dpi

import "testing"

func TestReadPCAP(t *testing.T) {
	dpi := newDPI()
	dpi.readPCAP("data/pcap/http.cap")
}

func TestReadPCAPErr(t *testing.T) {
	dpi := newDPI()
	_, err := dpi.readPCAP("data/pcap/nil.cap")
	if err == nil {
		t.Fail()
	}
}

func TestSetFilter(t *testing.T) {
	dpi := newDPI()
	handle, _ := dpi.readPCAP("data/pcap/http.cap")
	var filter = "tcp and port 80"
	dpi.setFilter(handle, filter)
}

func TestSetFilterErr(t *testing.T) {
	dpi := newDPI()
	handle, _ := dpi.readPCAP("data/pcap/http.cap")
	var filter = "foobar"
	dpi.setFilter(handle, filter)
}

func TestGetPacketChan(t *testing.T) {
	dpi := newDPI()
	handle, _ := dpi.readPCAP("data/pcap/http.cap")
	var i = 0
	for _ = range dpi.getPacketChan(handle) {
		i++
	}
	if i != 43 {
		t.Errorf("Expected 43 packages got %d", i)
	}
}

func TestTelnetDetect(t *testing.T) {
	dpi := newDPI()
	handle, _ := dpi.readPCAP("data/pcap/telnet-raw.pcap")
	var filter = "tcp"
	dpi.setFilter(handle, filter)
	telnetPackages := 0
	for packet := range dpi.getPacketChan(handle) {
		if dpi.detectTelnet(packet) == 1 {
			telnetPackages++
		}
	}
	if telnetPackages != 17 {
		t.Errorf("Expected 17 telnet packages got %d", telnetPackages)
	}
}

func TestHTTPDetect(t *testing.T) {
	dpi := newDPI()
	handle, _ := dpi.readPCAP("data/pcap/http.cap")
	var filter = "tcp and port 80"
	dpi.setFilter(handle, filter)
	httpPackages := 0
	for packet := range dpi.getPacketChan(handle) {
		if dpi.detectProtocol(packet) == 1 {
			httpPackages++
		}
	}
	if httpPackages != 9 {
		t.Errorf("Expected 9 HTTP packages got %d", httpPackages)
	}
}
