use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'		=> 'Crypt::Enigma',
    'VERSION_FROM'	=> 'Enigma.pm', # finds $VERSION
    'PREREQ_PM'		=> {}, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?    ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM => 'Enigma.pm', # retrieve abstract from module
       AUTHOR     => 'Alistair Mills <cpan@alizta.com>') : ()),
);
