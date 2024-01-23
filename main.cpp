#include "PackageClassifier.h"


int main() {
	PackageClassifier classifier;
	const char* pcapFile = "file.pcap";
	const char* csvFilename = "output.csv";

	classifier.capturePackets(pcapFile);
	classifier.classifyAndWriteToCSV(csvFilename);

	return 0;
}
