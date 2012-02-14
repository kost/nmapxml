#!/usr/bin/perl
# (C) Kost. Distributed under GPL.

use strict;
use XML::Simple;
use HTML::Template;
use Data::Dumper;

if ($#ARGV<0) {
	print STDERR "NMAP open port sum (C) Kost. Distributed under GPL.\n\n";
	print STDERR "Usage: $0 <nmap-file.xml> ...\n";
	print STDERR "Example: $0 nmap-host1.xml nmap-host2.xml\n";
	exit 0;
}

my $totalhosts=0;
my $totalup=0;
my $totalopen=0;
my $totalclosed=0;
my $totalfiltered=0;
my $totalother=0;
my $totalports=0;
my $begport=0;
my $endport=65535;
my $notscanned="Not scanned";
my %openports;

my @ohost;
while (my $nmapfile = shift) {
	print STDERR "Processing $nmapfile...\n";

my $nmapxml;
eval {
$nmapxml = XMLin($nmapfile, ForceArray => 1, KeyAttr => ''); 
} or die ("Check your XML file $nmapfile! Error parsing XML file: $!");

my @doneports;
if ({$nmapxml->{'scaninfo'}->[0]}) {
	
	my $scannedports=$nmapxml->{'scaninfo'}->[0]->{'services'};

	foreach my $entry (split(",",$scannedports)) {
		if ($entry =~ /-/) {
			my ($beg,$end) = split("-",$entry);
			for (my $i=$beg; $i<=$end; $i++) {
				push @doneports,$i;
			}
		} else {
			push @doneports, $entry;
		}
	}
} # if my $scaninfo ....

# foreach my $doneport (@doneports) {  print STDERR "=$doneport\n"; }

foreach my $host (@{$nmapxml->{'host'}}) {	
	my %hostinfo;
	my %hostports;

	$hostinfo{'addr'} = $host->{'address'}->[0]->{'addr'}; 
#	$totalhosts++;
#	$totalup++ if ($host->{'status'}->[0]->{'state'} eq "up");
	$hostinfo{'hostname'} = $host->{'hostnames'}->[0]->{'hostname'}->[0]->{'name'};
	if (($host->{'os'}->[0]->{'osclass'}) || ($host->{'os'}->[0]->{'osmatch'})) {
	$hostinfo{'type'}=$host->{'os'}->[0]->{'osclass'}->[0]->{'type'};
	$hostinfo{'name'}=$host->{'os'}->[0]->{'osmatch'}->[0]->{'name'};
	$hostinfo{'acc'}=$host->{'os'}->[0]->{'osmatch'}->[0]->{'accuracy'};
	}

	
	my @oports;
#	print Dumper (@{$host->{'ports'}->[0]->{'port'}});

	if (defined(@{$host->{'ports'}->[0]->{'port'}})) {
	if (@{$host->{'ports'}->[0]->{'port'}}) {
	foreach my $port (@{$host->{'ports'}->[0]->{'port'}}) {
		my ($fstate,$fstateo,$fstatec,$fstatef,$fstatea);
		$fstate=$port->{'state'}->[0]->{'state'};
		my $portnr=$port->{'portid'};
		$hostports{$portnr}=$fstate;
		if ($fstate eq "open") {
			$fstateo="1";	
			$totalopen++;
			$openports{$portnr}++;
		} elsif ($fstate eq "closed") {
			$fstatec="1";	
			$totalclosed++;
		} elsif ($fstate eq "filtered") {
			$fstatef="1";	
			$totalfiltered++;
		} else {
			$totalother++;
			$fstatea=$fstate;
		}
		my %portinfo=(
			'protocol' => $port->{'protocol'},
			'portid' => $port->{'portid'},
			'state' => $fstate,
			'open' => $fstateo,
			'closed' => $fstatec,
			'filtered' => $fstatef,
			'other' => $fstatea,
			'name' => $port->{'service'}->[0]->{'name'},
			'product' => $port->{'service'}->[0]->{'product'},
			'conf' => $port->{'service'}->[0]->{'conf'}
		);
		push @oports, \%portinfo;
		$hostinfo{'fportsopen'}="Y";
	} # foreach
	} # not empty
	} # defined
	$hostinfo{'ports'} = \@oports;

	my @extraports;
	if (defined(@{$host->{'ports'}->[0]->{'extraports'}})) {
	if ((@{$host->{'ports'}->[0]->{'extraports'}})) {
		foreach my $port (@{$host->{'ports'}->[0]->{'extraports'}}) {
			my ($fstateo,$fstatec,$fstatef,$fstatea);
			foreach my $doneport (@doneports) { 
				# print STDERR $doneport."-\n";
				if ($hostports{$doneport} eq $notscanned) {
					$hostports{$doneport} = $port->{'state'};
				}
			}
			if ($port->{'state'} eq "open") {
				$fstateo="1";	
			} elsif ($port->{'state'} eq "closed") {
				$fstatec="1";	
			} elsif ($port->{'state'} eq "filtered") {
				$fstatef="1";	
			} else {
				$fstatea=$port->{'state'};
			}
			my %extraport = (
				'count' => $port->{'count'},
				'state' => $port->{'state'},
				'open' => $fstateo,
				'closed' => $fstatec,
				'filtered' => $fstatef,
				'other' => $fstatea
			);
			$totalopen=$totalopen+$port->{'count'}*$fstateo;
			$totalclosed=$totalclosed+$port->{'count'}*$fstatec;
			$totalfiltered=$totalfiltered+$port->{'count'}*$fstatef;
			$totalother=$totalother+$port->{'count'}*$fstatea;
			push @extraports, \%extraport;
		}
		$hostinfo{'fextraports'}="Y";
	} # if (@{$...

	$hostinfo{'extraports'}=\@extraports;
	} # if(defined(...

	push @ohost, \%hostinfo;
}
	$totalhosts=$totalhosts+$nmapxml->{'runstats'}->[0]->{'hosts'}->[0]->{'total'};
	$totalup=$totalup+$nmapxml->{'runstats'}->[0]->{'hosts'}->[0]->{'up'};
}

while (my ($portnum, $count) = each(%openports)) {
	print $portnum.";".$count."\n";
}

$totalports=$totalopen+$totalclosed+$totalfiltered+$totalother;

print STDERR "Total host: $totalup up from $totalhosts hosts scanned\n";
print STDERR "Total ports:\n Open: $totalopen\n Closed: $totalclosed\n Filtered: $totalfiltered\n Other:$totalother\n(Total: $totalports ports scanned)\n";


