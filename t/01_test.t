# t/01_test.t - check module loading, etc

use Test::More tests => 2;

BEGIN { use_ok( 'Audio::M4pDecrypt' ); }

my $object = new Audio::M4pDecrypt;
isa_ok ($object, 'Audio::M4pDecrypt');

