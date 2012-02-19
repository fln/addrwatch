#!/usr/bin/perl

use MIME::Base64;

unless ($#ARGV == 0) {
	print "Usage: $0 BASE64_PACKET_DUMP > output_pcap_file.dump\n\n";
	print "Example: $0 AAAMn/ABASNFZ4mrCAYAAQgABgQAAQEjRWeJzcCoAAEAAAAAAAAAAAAA > malformed.dump\n";
	exit -1;
}

$pkt = decode_base64($ARGV[0]);
$global_header = pack "LSSLLLL", 0xa1b2c3d4, 2, 4, 0, 0, 9000, 1;
$pkt_header = pack 'LLLL', 0, 0, length $pkt, length $pkt;

print "$global_header$pkt_header$pkt";
