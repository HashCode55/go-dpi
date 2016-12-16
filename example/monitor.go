package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/chifflier/nfqueue-go/nfqueue"
	"github.com/coreos/go-iptables/iptables"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func sendNewPacket(payload *nfqueue.Payload, packetLayers ...gopacket.SerializableLayer) {
	buffer := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(
		buffer,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		packetLayers...,
	)
	outgoingPacket := buffer.Bytes()
	payload.SetVerdictModified(nfqueue.NF_ACCEPT, outgoingPacket)
}

func realCallback(payload *nfqueue.Payload) int {
	packet := gopacket.NewPacket(payload.Data, layers.LayerTypeIPv4, gopacket.Default)
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			if tcp.DstPort == 8888 {
				tcp.DstPort = 8000
				sendNewPacket(payload, ip, tcp)
				return 0
			}
			if tcp.SrcPort == 8000 {
				tcp.SrcPort = 8888
				sendNewPacket(payload, ip, tcp)
				return 0
			}
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
	ipt.Append("filter", "OUTPUT", "-p", "tcp", "-j", "NFQUEUE", "--queue-num", "0")
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
			_ = sig
			q.Close()
			err = ipt.ClearChain("filter", "INPUT")
			err = ipt.ClearChain("filter", "OUTPUT")
			if err != nil {
				panic(err)
			}
			os.Exit(0)
		}
	}()
	q.TryRun()
}
