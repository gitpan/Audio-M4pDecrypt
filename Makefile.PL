use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME         => 'Audio::M4pDecrypt',
    VERSION_FROM => 'lib/Audio/M4pDecrypt.pm', # finds $VERSION
    AUTHOR       => 'William Hererra (whererra@skylightview.com)',
    ABSTRACT     => 'Perl version of DeDRMS.',
    PREREQ_PM    => { Crypt::Rijndael => 0, Digest::MD5 => 0, Test::More => 0 },
);
