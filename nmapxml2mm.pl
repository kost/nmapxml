#!/usr/bin/perl
# (C) Kost. Distributed under GPL.

use strict;
use XML::Simple;
use Getopt::Long;
# use Data::Dumper;

my $mindmap;
my $fileperhost = 1;
my $nmapfile;
my $single;

my $stat = GetOptions(
	"i|in=s" => \$nmapfile,
	"o|out=s" => \$mindmap,
	"s|single" => \$single,
	"h|help|?" => \&help
);

$fileperhost=0 if ($single);

if (!defined($nmapfile) || (!defined($mindmap))) {
	help();
}

print STDERR "Using $mindmap as output\n";

print STDERR "Processing $nmapfile...\n";
my $nmapxml;
eval {
$nmapxml = XMLin($nmapfile, ForceArray => 1, KeyAttr => ''); 
} or die ("Check your XML file $nmapfile! Error parsing XML file: $!");

my $mindfile=$mindmap;
if ($fileperhost == 0) {
	open (OFILE,">$mindfile") or die ("Cannot open $mindmap for writting: $!");
	print OFILE '<map version="0.7.1">'."\n";
	print OFILE '<node TEXT="scan">'."\n";
	print OFILE '<node TEXT="hosts">'."\n";
} else {
	open (GFILE,">$mindmap.mm") or die ("Cannot open $mindmap for writting: $!");
	print GFILE '<map version="0.7.1">'."\n";
	print GFILE '<node TEXT="scan">'."\n";
	print GFILE '<node TEXT="hosts">'."\n";
}

foreach my $host (@{$nmapxml->{'host'}}) {	
	my %hostinfo;
	$mindfile=$mindmap."-".$host->{'address'}->[0]->{'addr'}.".mm";
	if ($fileperhost == 1) {
		open (OFILE,">$mindfile") or die ("Cannot open $mindmap for writting: $!");
		print OFILE '<map version="0.7.1">'."\n";
		print OFILE '<node TEXT="scan" LINK="'.$mindmap.'.mm">'."\n";
		print OFILE '<node TEXT="hosts">'."\n";

		print GFILE "<node TEXT=\"$host->{'address'}->[0]->{'addr'}\" LINK=\"$mindfile\">\n";
		print GFILE "</node>\n"; # host
	}
	print OFILE "<node TEXT=\"$host->{'address'}->[0]->{'addr'}\">\n";

	print OFILE '<node TEXT="dns">'."\n";
	print OFILE "<node TEXT=\"$host->{'hostnames'}->[0]->{'hostname'}->[0]->{'name'}\"/>\n";
	print OFILE "</node>\n"; # dns

	print OFILE '<node TEXT="OS">'."\n";
	if (($host->{'os'}->[0]->{'osclass'}) || ($host->{'os'}->[0]->{'osmatch'})) {
	print OFILE "<node TEXT=\"$host->{'os'}->[0]->{'osclass'}->[0]->{'type'},$hostinfo{'name'}=$host->{'os'}->[0]->{'osmatch'}->[0]->{'name'},$hostinfo{'acc'}=$host->{'os'}->[0]->{'osmatch'}->[0]->{'accuracy'}\"/>\n";
	}
	print OFILE "</node>\n"; # OS
	
#	print Dumper (@{$host->{'ports'}->[0]->{'port'}});

	print OFILE '<node TEXT="ports">'."\n";
	if (defined(@{$host->{'ports'}->[0]->{'port'}})) {
	print OFILE '<node TEXT="open">'."\n";
	if (@{$host->{'ports'}->[0]->{'port'}}) {
	foreach my $port (@{$host->{'ports'}->[0]->{'port'}}) {
		my $fstate;
		$fstate=$port->{'state'}->[0]->{'state'};
		if ($fstate eq "open") {
			print OFILE "<node TEXT=\"$port->{'protocol'}/$port->{'portid'}\">\n";
			print OFILE "<node TEXT=\"$port->{'service'}->[0]->{'name'};$port->{'service'}->[0]->{'product'};$port->{'service'}->[0]->{'conf'}\"/>\n";
			print OFILE "</node>\n";
		}
	} # foreach
	} # not empty
	print OFILE "</node>\n";
	} # defined

	if (defined(@{$host->{'ports'}->[0]->{'extraports'}})) {
	if ((@{$host->{'ports'}->[0]->{'extraports'}})) {
		print OFILE '<node TEXT="extra">'."\n";
		foreach my $port (@{$host->{'ports'}->[0]->{'extraports'}}) {
			print OFILE "<node TEXT=\"$port->{'state'}\">\n";
			print OFILE "<node TEXT=\"$port->{'count'}\"/>\n";
			print OFILE "</node>\n"; # state
		}
		print OFILE "</node>\n"; # extra 
	}
	}
	print OFILE "</node>\n";  # ports node

	print OFILE "</node>\n"; # host node
	if ($fileperhost == 1) {
		print OFILE "</node>\n"; # hosts
		print OFILE "</node>\n"; # scan
		print OFILE "</map>\n";
		close OFILE;
	}
}
if ($fileperhost == 0) {
	print OFILE "</node>\n"; # hosts
	print OFILE "</node>\n"; # scan
	print OFILE "</map>\n";
	close OFILE;
} else {
	print GFILE "</node>\n"; # hosts
	print GFILE "</node>\n"; # scan
	print GFILE "</map>\n";
	close GFILE;
}
	

sub help {
	print STDERR "NMAP XML to FreeMind(map) (C) Kost. Distributed under GPL.\n\n";
	print STDERR "Usage: $0 -o <mindmap> -i <nmap-file.xml>\n";
	print STDERR "Example: $0 -o nmap.mm -i nmap-host1.xml\n";
	exit 0;
}
	
