#! /usr/local/bin/perl

require LWP::UserAgent;

my $ua = LWP::UserAgent->new(timeout => 30);

foreach (@ARGV) {

	my $response = $ua->head("http://127.0.0.1:8080/$_");

	print $_ . "\t" . $response->code() . "\t" . $response->header('X-SAVI-Status') . "\n";
}
