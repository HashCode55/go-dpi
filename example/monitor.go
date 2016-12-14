package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/chifflier/nfqueue-go/nfqueue"
	"github.com/coreos/go-iptables/iptables"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// iptables -A INPUT -j NFQUEUE --queue-num 0

func realCallback(payload *nfqueue.Payload) int {
	//fmt.Println(hex.Dump(payload.Data))
	// Decode a packet
	packet := gopacket.NewPacket(payload.Data, layers.LayerTypeIPv4, gopacket.Default)
	// Get the TCP layer from this packet
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	eth, _ := ethLayer.(*layers.Ethernet)
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			// Get actual TCP data from this layer
			tcp, _ := tcpLayer.(*layers.TCP)
			fmt.Printf("From src port %d to dst port %d\n", tcp.SrcPort, tcp.DstPort)
			if tcp.DstPort == 8888 {
				tcp.DstPort = 8000
				buffer := gopacket.NewSerializeBuffer()
				gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{ComputeChecksums: true},
					eth,
					ip,
					tcp,
				)
				outgoingPacket := buffer.Bytes()
				payload.SetVerdictModified(nfqueue.NF_ACCEPT, outgoingPacket)
				return 0
			}
		}
		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			fmt.Printf("From src port %d to dst port %d\n", udp.SrcPort, udp.DstPort)
		}
	}
	payload.SetVerdict(nfqueue.NF_ACCEPT)
	return 0
}

func main() {
	ipt, err := iptables.New()
	if err != nil {
		panic(err)
	}
	ipt.Append("filter", "INPUT", "-p", "tcp", "-j", "NFQUEUE", "--queue-num", "0")
	q := new(nfqueue.Queue)
	q.SetCallback(realCallback)

	q.Init()
	defer q.Close()

	q.Unbind(syscall.AF_INET)
	q.Bind(syscall.AF_INET)
	q.CreateQueue(0)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for sig := range c {
			// sig is a ^C, handle it
			_ = sig
			q.Close()
			err = ipt.ClearChain("filter", "INPUT")
			if err != nil {
				log.Printf("ClearChain failed: %v\n", err)
			}

			fmt.Printf("bye\n")
			os.Exit(0)
		}
	}()
	q.TryRun()
}
