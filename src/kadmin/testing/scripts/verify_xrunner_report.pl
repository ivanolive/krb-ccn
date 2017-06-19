#!/usr/bin/perl

sub usage { die "usage: $0 reportfile\n"; }

$report = shift(@ARGV) || die &usage;

open(REPORT, $report) || die "Couldn't open $report: $!\n";

while(<REPORT>) {
    if (/Process termination:/ && !/\bOK\b/) {
	warn "Process termination not OK\n";
	$warnings++;
    } elsif (/Number of detected mismatches:\s*(\d+)/ && ($1 ne "0")) {
	warn "Number of detected mismatches = $1\n";
	$warnings++;
    } elsif (/Detailed Results Description/) {
	break;
    }
}

while(<REPORT>) {
    next if !/^\d+\s+/;

    split;

    if (($_[2] ne "run") &&
	($_[2] ne "OK") &&
	($_[2] ne "end-of-test")) {
	warn "Unexpected result code $_[2] from test $_[4]\n";
	$warnings++;
    }
}

if ($warnings) {
    warn "$warnings warnings.\n";
}

exit($warnings);
