#include "PackageClassifier.h"
#include <iostream>
#include <sstream>
#include <arpa/inet.h>


void PackageClassifier::capturePackets(const char* pcapFile) {

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_offline(pcapFile, errbuf);

	if (pcap == nullptr) {
		std::cerr << "Failed to open pcap file: " << errbuf << std::endl;
		return;
	}

	pcap_loop(pcap, 0, [](u_char* usr, const pcap_pkthdr* hdr, const u_char* pkt) {
	  reinterpret_cast<PackageClassifier*>(usr)->processPacket(pkt, hdr);
	}, reinterpret_cast<u_char*>(this));

	pcap_close(pcap);
}

void PackageClassifier::processPacket(const u_char* packet, const struct pcap_pkthdr* pkthdr) {
	const uint16_t ETHERTYPE_IP = 0x0800;
	const uint8_t IPV4 = 4;
	const uint8_t TCP = 6;
	const uint8_t UDP = 17;

	uint16_t etherType = (packet[12] << 8) | packet[13];
	if (etherType != ETHERTYPE_IP) { // If not an IPv4 package
		return;
	}

	// Extract version and header length, starts with 14-th byte
	uint8_t ipVersionAndHeaderLength = packet[14];
	uint8_t ipVersion = (ipVersionAndHeaderLength >> 4) & 0xF;
	if (ipVersion != IPV4) {
		return;
	}

	uint8_t protocol = packet[23];
	if (protocol == TCP || protocol == UDP) {
		in_addr srcIP, destIP;
		memcpy(&srcIP, &packet[26], sizeof(in_addr));
		memcpy(&destIP, &packet[30], sizeof(in_addr));

		uint16_t srcPort = (packet[34] << 8) | packet[35];
		uint16_t destPort = (packet[36] << 8) | packet[37];

		size_t packetLength = pkthdr->len;
		updatePackageData(srcIP, destIP, srcPort, destPort, packetLength);
	}
}

void PackageClassifier::updatePackageData(
	const in_addr& srcIP,
	const in_addr& destIP,
	uint16_t srcPort,
	uint16_t destPort,
	size_t packetLength
	) {
	std::stringstream keyStream;
	keyStream << inet_ntoa(srcIP) << ":" << srcPort << "-" << inet_ntoa(destIP) << ":" << destPort;
	std::string key = keyStream.str();

	PackageData& packetData = packageDataMap[key];
	packetData.source_ip = srcIP;
	packetData.aim_ip = destIP;
	packetData.source_port = srcPort;
	packetData.aim_port = destPort;
	packetData.number_of_packages++;
	packetData.number_of_bytes += packetLength;
}

void PackageClassifier::classifyAndWriteToCSV(const char* csvFilename) {
	// Get package data to CSV
	std::ofstream csvFile(csvFilename);
	csvFile << "Source IP, Aim IP, Source Port, Aim Port, Number of Packets, Number of Bytes\n";

	for (const auto& entry : packageDataMap) {
		const PackageData& packetData = entry.second;
		csvFile << inet_ntoa(packetData.source_ip) << ", "
				<< inet_ntoa(packetData.aim_ip) << ", "
				<< packetData.source_port << ", "
				<< packetData.aim_port << ", "
				<< packetData.number_of_packages << ", "
				<< packetData.number_of_bytes << "\n";
	}

	csvFile.close();
}
