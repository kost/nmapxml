#!/usr/bin/perl
# Reads nmap xml file and spits out to stdout http(s) servers in URL form
# (C) Vlatko Kosturjak, Kost. Distributed under GPL.

use strict;
use XML::Simple;

if ($#ARGV<0) {
	print STDERR "NMAP XML to HTTP(S) URLs (C) Kost. Distributed under GPL.\n\n";
	print STDERR "Usage: $0 <nmap-file.xml> ...\n";
	print STDERR "Example: $0 nmap-host1.xml\n";
	exit 0;
}

while (my $nmapfile=shift) {
print STDERR "Processing $nmapfile...\n";
my $nmapxml;
eval {
$nmapxml = XMLin($nmapfile, ForceArray => 1, KeyAttr => ''); 
} or die ("Check your XML file $nmapfile! Error parsing XML file: $!");

foreach my $host (@{$nmapxml->{'host'}}) {	
	my %hostinfo;
	
	if (defined(@{$host->{'ports'}->[0]->{'port'}})) {
	if (@{$host->{'ports'}->[0]->{'port'}}) {
	foreach my $port (@{$host->{'ports'}->[0]->{'port'}}) {
		my $fstate;
		$fstate=$port->{'state'}->[0]->{'state'};
		if ($fstate eq "open") {
			if ($port->{'service'}->[0]->{'name'} eq "http") {
				my $req;
				my $cmdline;
				if ($port->{'service'}->[0]->{'tunnel'} eq "ssl") {
					$req="https";
				} else {
					$req="http";
				}
					
				print "$req://$host->{'address'}->[0]->{'addr'}:$port->{'portid'}\n";
				
			}
		}
	} # foreach (port)
	} # not empty
	} # if (defined)
} # foreach (host)

} # while (nmapfile)


