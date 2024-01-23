#ifndef PACKET_CLASSIFIER_H
#define PACKET_CLASSIFIER_H


#include <pcap.h>
#include <netinet/in.h>
#include <string>
#include <unordered_map>
#include <fstream>


struct PackageData {
	in_addr source_ip;    // Source IP address
	in_addr aim_ip;   // Destination IP address
	uint16_t source_port; // Source port
	uint16_t aim_port; // Destination port
	size_t number_of_packages; // Number of packets
	size_t number_of_bytes;   // Number of bytes
};

class PackageClassifier {
 public:
	void capturePackets(const char* pcapFile);
	void processPacket(const u_char* packet, const struct pcap_pkthdr* pkthdr);
	void classifyAndWriteToCSV(const char* csvFilename);
 private:
	std::unordered_map<std::string, PackageData> packageDataMap;

	void updatePackageData
		(
		const in_addr& srcIP,
		const in_addr& destIP,
		uint16_t sourcePort,
		uint16_t destinationPort,
		size_t packetLength
		);
};

#endif // PACKET_CLASSIFIER_H
