#!/usr/local/bin/perl -w
use Crypt::Enigma;

if (! $ARGV[0]) {
	print "Usage: $0 <ROTORS> <RINGS> <INTIALSETTINGS> <INPUT>\n";
	exit ();
}

$rotors = $ARGV[0];
$rings = $ARGV[1];
$initial_settings = $ARGV[2];
@input = split (//, $ARGV[3]);

$enigma = Crypt::Enigma->new ();

$enigma->setup ($rotors, $rings, $initial_settings);
$enigma->stekker ("a", "b");

foreach $input (@input) {
	$output = $enigma->input ($input);
	$results .= $output;
}


print "Input is $ARGV[3]\n";
print "Result is $results\n";
