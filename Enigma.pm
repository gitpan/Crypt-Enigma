package Crypt::Enigma;

use 5.006;
use strict;
no strict 'refs';
use warnings;

require Exporter;

our @ISA = qw(Exporter);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration	use Crypt::Enigma ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
our %EXPORT_TAGS = ( 'all' => [ qw(
	
) ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our @EXPORT = qw(
	
);
our $VERSION = '1.1';


# Preloaded methods go here.

# Enigma.pm by Jason Blakey
# jblakey@frogboy.net


# 
# DEFINITIONS
#

# Define our rotors, where the notches are on each rotor, and the 
# reflector.
our (@ROTOR0) = qw (e k m f l g d q v z n t o w y h x u s p a i b r c j);
our (@ROTOR1) = qw (a j d k s i r u x b l h w t m c q g z n p y f v o e);
our (@ROTOR2) = qw (b d f h j l c p r t x v z n y e i w g a k m u s q o);
our (@ROTOR3) = qw (e s o v p z j a y q u i r h x l n f t g k d c m w b);
our (@ROTOR4) = qw (v z b r g i t y u p s d n h l x a w m j q o f e c k);

# To quiet the -w warnings...
if (@ROTOR0 and @ROTOR1 and @ROTOR2 and @ROTOR3 and @ROTOR4) {};

our (@NOTCHES) = qw (7 25 11 7 2);

our (@REFLECTOR) = qw (y r u h q s l d p x n g o k m i e b f z c w v j a t);

#
# SUBROUTINES 
#

sub new {
	my ($class) = $_[0];
	# Create a new anonymous hash...
	my ($self) = {};

	# Make it an object...
	bless ($self, $class);

	# And return the created object...
	return ($self);
}

sub setup {
	my ($self) = $_[0];
	my ($rotors) = $_[1];
	my ($ring_settings) = $_[2];
	my ($initial_settings) = $_[3];

	# Reverse the input so that they make sense...
	my (@rotors) = reverse (split (//, $rotors));
	my (@ring_settings) = reverse (split (//, $ring_settings));
	my (@initial_settings) = reverse (split (//, $initial_settings));

	our (%NOTCHES);

	#
	# So first, we need to put the rotors inside the 
	# enigma in the correct order and combination.
	#

	my ($rotor);
	foreach $rotor (0 .. $#rotors) {
		# Initialize the number of clicks on each rotor...
		$self->{ROTORS}->{$rotor}->{CLICKS} = 0;

		# Store the notch position for this rotor.
		$self->{ROTORS}->{$rotor}->{NOTCH} = $NOTCHES[$rotor];

		# Store the ring setting for this rotor.
		my ($ring_setting) = chr2num ($ring_settings[$rotor]);
		$self->{ROTORS}->{$rotor}->{RING_SETTING} = $ring_setting;

		# Determine the variable name for this rotor
		my ($rotorname) = "ROTOR".($rotors[$rotor] - 1);

		my ($input);
		foreach $input (0 .. $#{$rotorname}) {

			my ($output) = ${$rotorname}[$input];
			$output = chr2num ($output);

			my ($new_input) = ($input + $ring_setting) % 26;
			my ($new_output) = ($output - $ring_setting) % 26;

			$self->{ROTORS}->{$rotor}->{FORWARD}->{$new_input} = 
				$new_output;
			$self->{ROTORS}->{$rotor}->{REVERSE}->{$new_output} =
				$new_input;
		}

		#
		# And advance each rotor until it is in the requested 
		# initial position.
		#

		my ($initial_setting) = $initial_settings[$rotor];
		my ($required_turns) = 
			(chr2num ($initial_setting) - $ring_setting) % 26;

		while ($required_turns > 0) {
			$self->roll_rotor ($rotor);
			$required_turns--;
		}
	}

	# And return...
	return ();
}

sub stekker {
	my ($self) = $_[0];
	my ($input_chr) = $_[1];
	my ($output_chr) = $_[2];

	my ($input_num) = chr2num ($input_chr);
	my ($output_num) = chr2num ($output_chr);

	# Store the stekker'ed positions...
	$self->{STEKKER}->{$input_num} = $output_num;
	$self->{STEKKER}->{$output_num} = $input_num;
}

sub input {
	my ($self) = $_[0];
	my ($input_chr) = $_[1];

	our (%REFLECTOR);

	# First, we convert the letter to a number
	my ($input_num) = chr2num($input_chr);

	# Next, we go through the stekkerboard.
	# If the input character was stekker'ed...
	if (defined ($self->{STEKKER}->{$input_num})) {
		$input_num = $self->{STEKKER}->{$input_num};
	}

	# Next, we need to move the rotors forward by 1 click...
	$self->advance_rotors ();

	# Next, we go through the rotors forward.
	my ($rotor);
	foreach $rotor (sort (keys (%{$self->{ROTORS}}))) {
		$input_num = 
			$self->{ROTORS}->{$rotor}->{FORWARD}->{$input_num};
	}

	# Now, we go through the reflector.
	$input_chr = $REFLECTOR[$input_num];
	$input_num = chr2num ($input_chr);

	# Next, we go back through the rotors in REVERSE.
	foreach $rotor (reverse (sort (keys (%{$self->{ROTORS}})))) {
		$input_num = 
			$self->{ROTORS}->{$rotor}->{REVERSE}->{$input_num};
	}

	# Next, back through the Stekker.
	if (defined ($self->{STEKKER}->{$input_num})) {
		$input_num = $self->{STEKKER}->{$input_num};
	}

	# Convert the number back into a character.
	my ($output_char) = num2chr($input_num);

	# And finally return the result.
	return ($output_char);
}

sub advance_rotors {
	my ($self) = $_[0];

	# The first rotor always gets moved one click forward, so
	# default to a positive advance_check.
	my ($we_should_advance) = 1;

	# Step through each rotor...
	my ($rotor);
	foreach $rotor (sort (keys (%{$self->{ROTORS}}))) {

		# If we should advance this rotor...
		if ($we_should_advance) {

			# Now, we need to rotate the rotors values...
			$self->roll_rotor ($rotor);

			# If the new notch position is not 0, then
			# we leave advance_rotor set so that we will
			# advance the next rotor...

			my ($notch_position) = 
				$self->{ROTORS}->{$rotor}->{NOTCH};

			if ($notch_position != 0 ) {
				$we_should_advance = 0;
			}
		}
	}

	# And return.
	return ();
}

sub roll_rotor {
	my ($self) = $_[0];
	my ($rotor) = $_[1];

	my (%temp);

	#
	# Step through each transformation this rotor holds.
	#

	my ($position);
	foreach $position (keys (%{$self->{ROTORS}->{$rotor}->{FORWARD}})) {

		# move the position up one...
		my ($new_position) = ($position + 1) % 26;

		# And move the value for that position down one...
		my ($value) = 
			$self->{ROTORS}->{$rotor}->{FORWARD}->{$position};
		my ($new_value) = ($value - 1) % 26; 

		# Store the transformation in a temporary hash...
		$temp{$rotor}->{FORWARD}->{$new_position} = $new_value;
	}

	# Now, copy the temprotors over into rotors...
	foreach $position (sort (keys (%{$temp{$rotor}->{FORWARD}}))) {
		my ($value) = $temp{$rotor}->{FORWARD}->{$position};
		$self->{ROTORS}->{$rotor}->{FORWARD}->{$position} = $value;
		$self->{ROTORS}->{$rotor}->{REVERSE}->{$value}= $position;
	}

	# Next, we compute the new notch position for this rotor we just 
	# clicked.

	my ($current_notch) = $self->{ROTORS}->{$rotor}->{NOTCH};

	my ($new_notch) = ($current_notch - 1) % 26;
	$self->{ROTORS}->{$rotor}->{NOTCH} = $new_notch;

	# Update the number of clicks for this rotor.
	my ($clicks) = $self->{ROTORS}->{$rotor}->{CLICKS};
	$self->{ROTORS}->{$rotor}->{CLICKS} = $clicks + 1;

	# And return...
	return ();
}

sub view {
	my ($self) = $_[0];

	my ($view) = "";

	my ($rotor); 
	foreach $rotor (reverse (sort (keys (%{$self->{ROTORS}})))) {

		my ($clicks) = $self->{ROTORS}->{$rotor}->{CLICKS};
		my ($ring_setting) = $self->{ROTORS}->{$rotor}->{RING_SETTING};

		my ($num) = ($clicks + $ring_setting) % 26;
		my ($chr) = num2chr ($num);
		$view .= "$chr";
	}
	return ($view);
}

# A couple of number -> letter, letter -> number routines...
sub chr2num {
	my ($character) = $_[0];
	return (ord ($character) - 97);
}

sub num2chr {
	my ($number) = $_[0];
	return (chr($number + 97));
}

return (1);
__END__
# Below is stub documentation for your module. You better edit it!

=head1 NAME

Crypt::Enigma - Perl extension for emulating a World War II Enigma


=head1 SYNOPSIS

  use Crypt::Enigma;

  my($enigma) = Crypt::Enigma->new();


  # Set the enigma to the proper rotor, ring, and initial setting.
  $enigma->setup("312", "ABC", "ERZ");

  # Plugboard a to b, and b to a.
  $enigma->stekker("a", "b");

  # Input a single letter, and get the encrypted letter.
  my($output) = $enigma->input("A");

  # Input another letter, and get the output.
  $output = $enigma->input("W");


=head1 DESCRIPTION

See the documentation that came with the Crypt::Enigma package for
more information.

=head2 EXPORT

None by default.


=head1 AUTHOR

Jason Blakey, <lt>jblakey@frogboy.net<gt>

=head1 SEE ALSO

http://www.frogboy.net/Enigma

=cut
