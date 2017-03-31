#!/usr/bin/env perl

use strict;
use warnings;
use URI::Escape;
use MIME::Base64 qw( decode_base64 );

if (!(@ARGV > 0)) {	
	usage();
} else {
	my $file = shift(@ARGV);
	if (-f $file) {
		print "Parsing $file\n";
		open(my $fh,'<:encoding(UTF-8)',$file) or die "Could not open $file! $!";
		while(my $r = <$fh>) {
			chomp $r;
			my ($i,$j) = split(/order=/, $r);
			$i =~ s/192.168.1.23 - -\ //g;
			$i =~ s/\"GET \/admin\/\?action=membres\&//g;
			$i =~ s/18\/Jun\/2015://g;
			$j =~ s/\ HTTP.*$//g;
			$j = decode_base64(uri_unescape($j));
			print "$i\t$j\n";
		}
	} else {
		print "$file seems not to exist\n";
		&usage();
	}
}



sub usage() {
	print "Usage: $0 <file to parse>";
}