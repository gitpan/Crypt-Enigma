package Crypt::Enigma;

$VERSION = "0.01";

use strict;

sub new {
	my $class = shift;
	my @rotors = reverse( split(' ', shift) );
	my @startLetter = reverse( split('', shift) );
	my @ringSetting = reverse( split(' ', shift) );
	my $reflector = shift;

	# Save the settings
	my $self = {
		rotorObjects => undef,
		reflectorObject => undef,
		settings => {
				rotors    => \@rotors,
				letters   => \@startLetter,
				rings     => \@ringSetting,
				reflector => $reflector,
			},
	};
	bless $self, $class;

	my $count = 0;
  foreach ( @rotors ) {
		# init called with (rotorName, startLetter, ringSetting)
		my $rotorObj = $self->_initRotor( $rotors[$count], $startLetter[$count], $ringSetting[$count] );
    push @{$self->{rotorObjects}}, $rotorObj;
		# save the rotor settings
		$count++;
	};

	# CREATE REFLECTOR
	my $className = 'Crypt::Enigma::Reflectors::'.$reflector;
	$self->{reflectorObject} = $className->new;

	return( $self );
};


sub _initRotor {
	my $self = shift;
	my $rotorName = shift;
	my $startLetter = shift;
	my $ringSetting = shift;

	# Do some checking
	unless( $rotorName =~ /^Rotor(I|II|III|IV|V|VI|VII|VIII|Beta|Gamma)$/ ) {
		print "Invalid rotor name: $rotorName\n";
		exit( 1 );
	};
	unless( $startLetter =~ /^[A-Za-z]$/ ) {
		print "Invalid initial setting: $startLetter\n";
		exit( 1 );
	};
	unless( ($ringSetting =~ /[0-9]$/) && ($ringSetting >= 0) && ($ringSetting <= 25) ) {
		print "Invalid ring setting: $ringSetting\n";
		exit( 1 );
	}

	my $className = 'Crypt::Enigma::Rotors::'.$rotorName;
	my $rotor = $className->new( $startLetter, $ringSetting );

	return( $rotor );
};


sub cipher {
	my $self = shift;
	my $plainText = lc(shift);
	my $cipherText = '';

	foreach my $letter ( split('', $plainText) ) {
		# next if the text is not alpha
		if( $letter !~ /[A-Za-z]/ ) {
			next;
		};

		# fwd cycle
		my $count = 0;
		foreach( @{$self->{rotorObjects}} ) {
			# We always rotate the first scrambler
			if( $count == 0 ) {
				$_->_rotateDisk;
			};
			$letter = $_->fwdCipher( $letter );
			# rotate the next disk, if there is one
			if( $_->_getFlag('rotateNext') && ($count != 2) ) {
				$self->_cycleNextRotor( $self->{rotorObjects}->[$count+1] );
				$_->_setFlag( rotateNext => 0 );
			};
			$count++;
		};

		# reflector
		$letter = $self->reflect( $letter );

		# rev cycle
		foreach( reverse(@{$self->{rotorObjects}}) ) {
			$letter = $_->revCipher( $letter );
		};

		$cipherText .= $letter;
	};
	# return uppercase ciphertext, like the original :)
	return( uc($cipherText) );
};

# alter the input using the reflector
sub reflect {
	my $self = shift;
	my $inputLetter = shift;

	my $outputLetter = $self->{reflectorObject}->reflect( $inputLetter );

	return( $outputLetter );
};


# Rotate the next rotor
sub _cycleNextRotor {
	my $self = shift;
	my $rotorObj = shift;
	$rotorObj->_rotateDisk;

	return;
};


sub getMachineSettings {
	my $self = shift;

	return( $self->{settings} );
};


package Crypt::Enigma::Reflectors;

use strict;

sub reflect {
	my $self = shift;
	my $inputLetter = shift;

  my $intInputLetter = ord($inputLetter) - 97;

  my $outputLetter = ${$self->{alphabet}}[$intInputLetter];

  return( $outputLetter );
};


package Crypt::Enigma::Reflectors::ReflectorB;

@Crypt::Enigma::Reflectors::ReflectorB::ISA = qw(Crypt::Enigma::Reflectors);

sub new {
	my $class = shift;

	my $self = {
		'alphabet' => [ 
			'y', 'r', 'u', 'h', 'q', 's', 'l', 'd', 'p', 'x', 'n', 'g', 'o', 'k', 'm', 'i', 'e', 'b', 'f', 'z', 'c', 'w', 'v', 'j', 'a', 't'
		],
	};
	bless $self, $class;

	return( $self );
};


package Crypt::Enigma::Reflectors::ReflectorBdunn;


@Crypt::Enigma::Reflectors::ReflectorBdunn::ISA = qw(Crypt::Enigma::Reflectors);

sub new {
	my $class = shift;

	my $self = {
		'alphabet' => [ 
			'e', 'n', 'k', 'q', 'a', 'u', 'y', 'w', 'j', 'i', 'c', 'o', 'p', 'b', 'l', 'm', 'd', 'x', 'z', 'v', 'f', 't', 'h', 'r', 'g', 's'
		],
	};
	bless $self, $class;

	return( $self );
};


package Crypt::Enigma::Reflectors::ReflectorC;

@Crypt::Enigma::Reflectors::ReflectorC::ISA = qw(Crypt::Enigma::Reflectors);

sub new {
	my $class = shift;

	my $self = {
		'alphabet' => [ 
			'f', 'n', 'p', 'j', 'i', 'a', 'o', 'y', 'e', 'd', 'r', 'z', 'x', 'w', 'g', 'c', 't', 'k', 'u', 'q', 's', 'b', 'n', 'm', 'h', 'l'
		],
	};
	bless $self, $class;

	return( $self );
};


package Crypt::Enigma::Reflectors::ReflectorCdunn;

@Crypt::Enigma::Reflectors::ReflectorCdunn::ISA = qw(Crypt::Enigma::Reflectors);

sub new {
	my $class = shift;

	my $self = {
		'alphabet' => [ 
			'r', 'd', 'o', 'b', 'j', 'n', 't', 'k', 'v', 'e', 'h', 'm', 'l', 'f', 'c', 'w', 'z', 'a', 'x', 'g', 'y', 'i', 'p', 's', 'u', 'q'
		],
	};
	bless $self, $class;

	return( $self );
};


package Crypt::Enigma::Rotors;

use strict;

sub _init {
	my $self = shift;
	my $startLetter = shift;

	my $intStartLetter = ord($startLetter) - 97;

	for( my $count = 0; $count < $intStartLetter; $count++ ) {
		# rotate the letters
		my $letter = pop @{$self->{alphabet}};
		unshift @{$self->{alphabet}}, $letter;
		$self->{cycleLetterPosition} == 0 ? $self->{cycleLetterPosition} = 25 : $self->{cycleLetterPosition}--;
	};

	return( 0 );
};


sub fwdCipher {
	my $self = shift;
	my $inputLetter = shift;

	my $intInputLetter = ( ord($inputLetter) - 97 + $self->{ringSetting} ) % 26;
	my $outputLetter = ${$self->{alphabet}}[$intInputLetter];

	return( $outputLetter );
};


sub revCipher {
	my $self = shift;
	my $inputLetter = shift;
	my $outputLetter;

	my $count = 0;
	foreach ( @{$self->{alphabet}} ) {
		if( $inputLetter eq $_ ) {
				$outputLetter = chr((($count - $self->{ringSetting} + 26) % 26) + 97);
			};
		$count++;
	};
	return( $outputLetter );
};


# rotate the polyalphabetic substitution by 1 letter
sub _rotateDisk {
	my $self = shift;

	my $letter = pop @{$self->{alphabet}};
	unshift @{$self->{alphabet}}, $letter;

	if( $self->{cycleLetterPosition} == 0 ) {
		$self->_setFlag( rotateNext => 1 );
		$self->{cycleLetterPosition} = 25;
	}
	else {
		$self->{cycleLetterPosition}--;
	};

	return( 0 );
};


sub _setFlag {
	my $self = shift;
	my $flag = shift;
	my $bool = shift;

	$self->{flags}->{$flag} = $bool;

	return( 1 );
};

sub _getFlag {
	my $self = shift;
	my $flag = shift;

	if( defined($self->{flags}->{$flag}) ) {
		return( $self->{flags}->{$flag} );
	};

	return( 0 );
};


package Crypt::Enigma::Rotors::RotorI;

@Crypt::Enigma::Rotors::RotorI::ISA = qw(Crypt::Enigma::Rotors);

sub new {
	my $class = shift;
	my $startLetter = shift;
	my $ringSetting = shift;

	my $self = {
		'cycleLetterPosition' => (16 + $ringSetting) % 25,
		'ringSetting' => $ringSetting,
		'alphabet' => [
			'b', 'd', 'f', 'h', 'j', 'l', 'c', 'p', 'r', 't', 'x', 'v', 'z', 'n', 'y', 'e', 'i', 'w', 'g', 'a', 'k', 'm', 'u', 's', 'q', 'o'
			]
	};
	bless $self, $class;

	$self->_init( $startLetter );

	return( $self );
};


package Crypt::Enigma::Rotors::RotorII;

@Crypt::Enigma::Rotors::RotorII::ISA = qw(Crypt::Enigma::Rotors);

sub new {
	my $class = shift;
	my $startLetter = shift;
	my $ringSetting = shift;

	my $self = {
		'cycleLetterPosition' => (5 + $ringSetting) % 25,
		'ringSetting' => $ringSetting,
		'alphabet' => [
			'a', 'j', 'd', 'k', 's', 'i', 'r', 'u', 'x', 'b', 'l', 'h', 'w', 't', 'm', 'c', 'q', 'g', 'z', 'n', 'p', 'y', 'f', 'v', 'o', 'e'
			]
	};
	bless $self, $class;

	$self->_init( $startLetter );

	return( $self );
};


package Crypt::Enigma::Rotors::RotorIII;

@Crypt::Enigma::Rotors::RotorIII::ISA = qw(Crypt::Enigma::Rotors);

sub new {
	my $class = shift;
	my $startLetter = shift;
	my $ringSetting = shift;

	my $self = {
		'cycleLetterPosition' => (22 + $ringSetting) % 25,
		'ringSetting' => $ringSetting,
		'alphabet' => [
			'e', 'k', 'm', 'f', 'l', 'g', 'd', 'q', 'v', 'z', 'n', 't', 'o', 'w', 'y', 'h', 'x', 'u', 's', 'p', 'a', 'i', 'b', 'r', 'c', 'j'
			]
	};
	bless $self, $class;

	$self->_init( $startLetter );

	return( $self );
};


package Crypt::Enigma::Rotors::RotorIV;

@Crypt::Enigma::Rotors::RotorIV::ISA = qw(Crypt::Enigma::Rotors);


sub new {
	my $class = shift;
	my $startLetter = shift;
	my $ringSetting = shift;

	my $self = {
		'cycleLetterPosition' => (10 + $ringSetting) % 25,
		'ringSetting' => $ringSetting,
		'alphabet' => [
'e', 's', 'o', 'v', 'p', 'z', 'j', 'a', 'y', 'q', 'u', 'i', 'r', 'h', 'x', 'l', 'n', 'f', 't', 'g', 'k', 'd', 'c', 'm', 'w', 'b'
			]
	};
	bless $self, $class;

	$self->_init( $startLetter );

	return( $self );
};


package Crypt::Enigma::Rotors::RotorVI;

@Crypt::Enigma::Rotors::RotorVI::ISA = qw(Crypt::Enigma::Rotors);


sub new {
	my $class = shift;
	my $startLetter = shift;
	my $ringSetting = shift;

	my $self = {
		'cycleLetterPosition' => (13 + $ringSetting) % 25,
		'ringSetting' => $ringSetting,
		'alphabet' => [
'j', 'p', 'g', 'v', 'o', 'u', 'm', 'f', 'y', 'q', 'b', 'e', 'n', 'h', 'z', 'r', 'd', 'k', 'a', 's', 'x', 'l', 'i', 'c', 't', 'w'
			]
	};
	bless $self, $class;

	$self->_init( $startLetter );

	return( $self );
};


package Crypt::Enigma::Rotors::RotorV;

@Crypt::Enigma::Rotors::RotorV::ISA = qw(Crypt::Enigma::Rotors);


sub new {
	my $class = shift;
	my $startLetter = shift;
	my $ringSetting = shift;

	my $self = {
		'cycleLetterPosition' => (0 + $ringSetting) % 25,
		'ringSetting' => $ringSetting,
		'alphabet' => [
'v', 'z', 'b', 'r', 'g', 'i', 't', 'y', 'u', 'p', 's', 'd', 'n', 'h', 'l', 'x', 'a', 'w', 'm', 'j', 'q', 'o', 'f', 'e', 'c', 'k'
			]
	};
	bless $self, $class;

	$self->_init( $startLetter );

	return( $self );
};


package Crypt::Enigma::Rotors::RotorVII;

@Crypt::Enigma::Rotors::RotorVII::ISA = qw(Crypt::Enigma::Rotors);


sub new {
	my $class = shift;
	my $startLetter = shift;
	my $ringSetting = shift;

	my $self = {
		'cycleLetterPosition' => (13 + $ringSetting) % 25,
		'ringSetting' => $ringSetting,
		'alphabet' => [
'n', 'z', 'j', 'h', 'g', 'r', 'c', 'x', 'm', 'y', 's', 'w', 'b', 'o', 'u', 'f', 'a', 'i', 'v', 'l', 'p', 'e', 'k', 'q', 'd', 't'
			]
	};
	bless $self, $class;

	$self->_init( $startLetter );

	return( $self );
};



package Crypt::Enigma::Rotors::RotorVIII;

@Crypt::Enigma::Rotors::RotorVIII::ISA = qw(Crypt::Enigma::Rotors);


sub new {
	my $class = shift;
	my $startLetter = shift;
	my $ringSetting = shift;

	my $self = {
		'cycleLetterPosition' => (13 + $ringSetting) % 25,
		'ringSetting' => $ringSetting,
		'alphabet' => [
'f', 'k', 'q', 'h', 't', 'l', 'x', 'o', 'c', 'b', 'j', 's', 'p', 'd', 'z', 'r', 'a', 'm', 'e', 'w', 'n', 'i', 'u', 'y', 'g', 'v'
			]
	};
	bless $self, $class;

	$self->_init( $startLetter );

	return( $self );
};



package Crypt::Enigma::Rotors::RotorBeta;

@Crypt::Enigma::Rotors::RotorBeta::ISA = qw(Crypt::Enigma::Rotors);


sub new {
	my $class = shift;
	my $startLetter = shift;
	my $ringSetting = shift;

	my $self = {
		'cycleLetterPosition' => (13 + $ringSetting) % 25,
		'ringSetting' => $ringSetting,
		'alphabet' => [
'l', 'e', 'y', 'j', 'v', 'c', 'n', 'i', 'x', 'w', 'p', 'b', 'q', 'm', 'd', 'r', 't', 'a', 'k', 'z', 'g', 'f', 'u', 'h', 'o', 's'
			]
	};
	bless $self, $class;

	$self->_init( $startLetter );

	return( $self );
};



package Crypt::Enigma::Rotors::RotorGamma;

@Crypt::Enigma::Rotors::RotorGamma::ISA = qw(Crypt::Enigma::Rotors);


sub new {
	my $class = shift;
	my $startLetter = shift;
	my $ringSetting = shift;

	my $self = {
		'cycleLetterPosition' => (13 + $ringSetting) % 25,
		'ringSetting' => $ringSetting,
		'alphabet' => [
'f', 's', 'o', 'k', 'a', 'n', 'u', 'e', 'r', 'h', 'm', 'b', 't', 'i', 'y', 'c', 'w', 'l', 'q', 'p', 'z', 'x', 'v', 'g', 'j', 'd'
			]
	};
	bless $self, $class;

	$self->_init( $startLetter );

	return( $self );
};



1;

=head1 NAME

Crypt::Enigma - Perl implementation of the Enigma cipher


=head1 SYNOPSIS

  use Crypt::Enigma;

  $enigma = Crypt::Enigma->new(
		'RotorIII', 'RotorII', 'RotorI', 'aaz', '0 0 0' 'ReflectorB' );


  # Encode the plaintext
  $cipher_text = $enigma->cipher( $plain_text );

  # Decode the ciphertext 
  $plain_text = $enigma->cipher( $cipher_text );


=head1 DESCRIPTION

See the documentation that came with the Crypt::Enigma package for
more information.

=head2 EXPORT

None by default.


=head1 AUTHOR

Alistair Mills, <lt>cpan@alizta.com<gt>

=cut
