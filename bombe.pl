#!/usr/bin/perl -w
use strict;
use Crypt::Enigma;

# Make sure that the output is not buffered...
$| = 1;


# Check our input.
if (!@ARGV) {
	print "Usage: $0 <plaintext> <cipertext> <loop positions> <num rotors>\n";
	print "Example: $0 akldfaa kdkdkdkd 1.2.3 3\n";
	exit ();
}


# Get our input from the command line.
my (@plaintext) = split (//, $ARGV[0]);
my (@ciphertext) = split (//, $ARGV[1]);
my (@loops) = split (/\./, $ARGV[2]);
my ($num_rotors) = $ARGV[3];


# Find all possible $num_rotors combinations of 12345.
my (@array) = qw (1 2 3 4 5);
my (@combos) = find_combos (\@array, $num_rotors);

# Build our initial enigma settings...
# We start with all a's...
my ($isetting) = "";
my ($i);
foreach $i (1 .. $num_rotors) {
	$isetting .= "a";
}


# For each possible combination of rotors...
my ($combo);
foreach $combo (@combos) {

	# Initialize our views array...
	my (@views) = ();

	# Initalize our group of enigmas.
	my (%enigmas);
	# Create an enigma for each link in the loop...
	my ($link);
	foreach $link (@loops) {

		$enigmas{$link} = Enigma->new();
		$enigmas{$link}->setup($combo, $isetting, $isetting);

		# Advance this enigma the proper number of turns...
		my ($i);
		for ($i = $link; $i > 0; $i--) {

			# We only need to remember the views of
			# the first enigma.	
			if ($link eq $loops[0]) {	
				# Look at the enigma, and remember
				# each view for each forward rotation.
				my ($view) = $enigmas{$link}->view();
				push (@views, $view);
			}

			# Advance the enigma...
			$enigmas{$link}->advance_rotors();
		}
	}

	# Store the final view for loops[0] in @views...
	my ($view) = $enigmas{$loops[0]}->view();
	push (@views, $view);

	# Next, using the enigma setup we have created, 
	# attempt the encryption. If we get #@loops 
	# matches, then we have found a state in which 
	# all links of the loop are true.

	print "Scanning rotor combination $combo\n";

	# For every possible positional combination of rotors...
	# 26^num_rotors...
	foreach $i (1 .. (26**$num_rotors)) {

		# Initialize the number of successful input/output matches.
		my ($num_matches) = 0;

		# Step though each enigma for this combination
		foreach $link (sort (keys (%enigmas))) {

			# We only need to remember the views of the
			# first enigma...
			if ($link eq $loops[0]) {
				# remove the first in @views,
				# and put the current view into @views.

				shift (@views);
				$view = $enigmas{$link}->view();
				push (@views, $view);
			}

			# Figure out the input and the output we are looking for.
			my ($input) = $plaintext[$link];
			my ($output) = $ciphertext[$link];

			# Encrypt the input...
			my ($result) = $enigmas{$link}->input($input);

			# If the result we get is the output we were
			# looking for, add one to num_matches.
			if ($output eq $result) {
				$num_matches++;
			}
		}

		# Only update the user on results if we have $#loops
		# or greater matches.
		if ($num_matches >= $#loops) {
			print "$num_matches";

			# And if we have $#loops + 1 matches (all)...
			if ($num_matches == ($#loops + 1)) {
				# print the good news.
				print "\nMatch for rotor combo $combo - try inital of $views[0]\n";
			}
		}
	}
}


sub find_combos {
	my ($arrayref) = $_[0];
	my ($combo_length) = $_[1];
	my (@combos) = ();

	my (@array) = @$arrayref;

	# if the combo_length is 1 - then we have no work to do...
	if ($combo_length == 1) {
		return (@array);
	}

	foreach $i (0 .. $#array) {
		my ($char) = $array[$i];
		my (@temp_array) = @array;
		my ($new_length) = $combo_length - 1;

		# Remove the current element from the array...
		splice (@temp_array, $i, 1);

		# call find_combos again with the new, shorter array...
		my (@results) = find_combos (\@temp_array, $new_length);

		# Push the results into @combos
		my ($result);
		foreach $result (@results) {
			push (@combos, "$char$result");
		}
	}

	# And return the results...
	return (@combos);
}
