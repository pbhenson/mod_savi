#! /usr/bin/perl -w

#
# Sophos scanner/IDE file update script
#
# Paul B. Henson <henson@acm.org>
#
# Copyright (c) 2001-2002 Paul B. Henson -- see COPYRIGHT file for details
#

use strict;

 
use LWP::UserAgent;

my $ua = LWP::UserAgent->new();
my $realm = 'Sophos software';
my $username = '<username>';
my $password = '<password>';
my $platform = 'solaris.sparc.tar.Z';
my $ide_dir = '/opt/local/etc/sophos';
my $lib_dir = '/opt/local/lib';
my $bin_dir = '/opt/local/sbin';
my $tmp_dir = '/var/amavis/sophos';
my $reload;

my $version = sweep_version();

$version =~ /^\d+$/ or
	print STDERR "failed to acquire existing Sophos version\n" and exit(1);

if (defined($ARGV[0]) && $ARGV[0] eq '-m') {

	$ua->credentials('downloads.sophos.com:80', $realm, $username, $password);

	my $request = HTTP::Request->new('GET', "http://downloads.sophos.com/sophos/products/full/$platform");

	my $response = $ua->request($request, "$tmp_dir/new.tar.Z");

	if (! $response->is_success()) {

		unlink "$tmp_dir/new.tar.Z";
		print STDERR "failed to retrieve Sophos monthly update: " . $response->status_line() . "\n";
		exit(1);
	}

	system("cd $tmp_dir; /usr/bin/zcat new.tar.Z | /usr/bin/tar xf -; rm -f new.tar.Z");

	my $sweep = "$tmp_dir/sav-install/sweep";
	my $libsavi = glob("$tmp_dir/sav-install/libsavi.so.*");
	my $vdl = glob("$tmp_dir/sav-install/vdl-*.dat");

	if (!(-f $sweep && -f $libsavi && -f $vdl)) {

		system("/usr/bin/rm -rf $tmp_dir/sav-install");
		print STDERR "failed to extract Sophos monthly update\n";
		exit(1);
	}

	system("/usr/bin/rm -f $ide_dir/*");
	system("/usr/bin/cp $vdl $ide_dir/vdl.dat");

	unlink("$lib_dir/libsavi.so.2");
	system("/usr/bin/cp $libsavi $lib_dir/libsavi.so.2");

	unlink("$bin_dir/sweep");
	system("/usr/bin/cp $sweep $bin_dir/sweep");

	my $new_version = sweep_version();

	$new_version =~ /^\d+$/ && $version != $new_version or
		print STDERR "failed to acquire new and improved Sophos version: previous = $version, new = $new_version\n";

	system("/usr/bin/rm -rf $tmp_dir/sav-install");

	$reload = 1;
}
else {

	my $response = $ua->get("http://www.sophos.com/downloads/ide/${version}_list.txt");

	$response->is_success() or
		print STDERR "failed to retrieve IDE list file: " . $response->status_line() . "\n" and exit(1);

	foreach my $ide_url (split(/\n/, ${$response->content_ref()})) {

		$ide_url =~ m#^.*/([^/]*)$#;
		my $ide_file = $1;

		my $ide_exists = -f "$ide_dir/$ide_file";

		my $response = $ua->mirror($ide_url, "$ide_dir/$ide_file");

		if ($response->is_success()) {

			$reload = 1;
		}
		elsif ($response->code() != 304) {

			unlink "$ide_dir/$ide_file" unless $ide_exists;
			print STDERR "failed to retrieve IDE file $ide_file: " . $response->status_line() . "\n";
		}
	}
}

system('/etc/init.d/httpd reload > /dev/null') if $reload;


sub sweep_version {

	$ENV{LD_LIBRARY_PATH} = $lib_dir;
	$ENV{SAV_IDE} = $ide_dir;

	my $sweep_output = `$bin_dir/sweep -v`;

	$sweep_output =~ s/^.*Product version           : ([^\n]*).*$/$1/s;
	$sweep_output =~ s/\.//g;

	return $sweep_output;
}

