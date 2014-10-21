#!/usr/bin/perl -w

use Crypt::Enigma;

unless( defined($ARGV[0]) ) {
	print "Usage: ./enigma.pl 'plain text or encrypted string'\n";
	exit( 0 );
};

my $text = $ARGV[0];

my $enigma = Crypt::Enigma->new;

print "Plain text:\t$text\n";

$enigma->setRotor( 'RotorVII', 'A', '0', 2 );

print "Cipher Text:\t", $enigma->cipher( $text ), " \n";

$enigma->dumpSettings;

