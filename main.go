package main

import (
	"flag"
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/k0kubun/pp/v3"
)

func main() {
	var interfaceName string
	var address string
	var mac string
	var macAddr net.HardwareAddr
	flag.StringVar(&interfaceName, "i", "eth0", "Interface name")
	flag.StringVar(&address, "a", "127.0.0.1", "IP address")
	flag.StringVar(&mac, "m", "", "MAC address (optional)")
	flag.Parse()

	ipaddr := net.ParseIP(address)
	if ipaddr == nil {
		log.Fatalf("Invalid IP address: %s", address)
	}

	if mac == "" {
		iface, err := net.InterfaceByName(interfaceName)
		if err != nil {
			log.Fatal(err)
		}
		macAddr = iface.HardwareAddr
	} else {
		var err error
		macAddr, err = net.ParseMAC(mac)
		if err != nil {
			log.Fatalf("Invalid MAC address: %s", mac)
		}
	}

	handle, err := pcap.OpenLive(interfaceName, 1500, false, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	err = handle.SetBPFFilter("arp")
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Interface: %s macaddr=%s", interfaceName, macAddr)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		arpLayer := packet.Layer(layers.LayerTypeARP)
		if arpLayer == nil {
			continue
		}
		arp, _ := arpLayer.(*layers.ARP)

		// ARP Requset 以外は処理しない
		if arp.Operation != layers.ARPRequest {
			continue
		}

		// 指定されたIPアドレス以外は処理しない
		if !ipaddr.Equal(net.IP(arp.DstProtAddress)) {
			continue
		}

		log.Printf("ARP request: %s -> %s", net.IP(arp.SourceProtAddress), net.IP(arp.DstProtAddress))

		replayArp := layers.ARP{
			AddrType:          layers.LinkTypeEthernet,
			Protocol:          layers.EthernetTypeIPv4,
			HwAddressSize:     6,
			ProtAddressSize:   4,
			Operation:         layers.ARPReply,
			SourceHwAddress:   []byte(macAddr),
			SourceProtAddress: arp.DstProtAddress,
			DstHwAddress:      arp.SourceHwAddress,
			DstProtAddress:    arp.SourceProtAddress,
		}

		eth := layers.Ethernet{
			SrcMAC:       macAddr,
			DstMAC:       arp.SourceHwAddress,
			EthernetType: layers.EthernetTypeARP,
		}

		buf := gopacket.NewSerializeBuffer()
		err = gopacket.SerializeLayers(buf, gopacket.SerializeOptions{},
			&eth,
			&replayArp,
		)
		if err != nil {
			log.Printf("SerializeLayers error: %s", err)
			continue
		}

		pp.Println(buf)

		err = handle.WritePacketData(buf.Bytes())
		if err != nil {
			log.Printf("WritePacketData error: %s", err)
			continue
		}
	}
}
