package Audio::M4pDecrypt;

require 5.004;
use strict;
use warnings;
use Carp;
use vars qw($VERSION);
$VERSION = '0.05';

use Crypt::Rijndael;
use Digest::MD5;

my ( $AtomDRMS, $AtomMP4A, $AtomSINF, $AtomUSER, $AtomKEY, 
     $AtomIVIV, $AtomNAME, $AtomPRIV, $AtomSTSZ, $AtomMDAT ) =
   ( "drms",    "mp4a",    "sinf",    "user",    "key ", 
     "iviv",    "name",    "priv",    "stsz",    "mdat"    );

sub new {
    my($class, %args) = @_;
    my $self = {};
    bless($self, $class);
    foreach my $k (qw( strHome sPfix dirSep )) 
      { $self->{$k} = $args{$k} if $args{$k} }
    unless($self->{strHome}) {
        if($ENV{APPDATA}) { $self->{strHome} = $ENV{APPDATA} }
        elsif($ENV{HOME}) { $self->{strHome} = $ENV{HOME} }
        else { $self->{strHome} = '~' }
    }
    unless($self->{sPfix}) {
        if($^O =~ /Win/) { $self->{sPfix} = '' }
        else { $self->{sPfix} = '.' }
    }
    $self->{dirSep} ||= '/';
    return $self;
}

sub GetAtomPos {
    my($self, $atom) = @_;
    my $idx = index($self->{sbuffer}, substr($atom, 0, 4));
    if($idx >= 0) { return $idx } else { croak "Atom $atom not found." } 
}

sub GetAtomSize {
    my($self, $pos) = @_;
    return unpack( 'N', substr($self->{sbuffer}, $pos - 4, 4) );
}    

sub GetAtomData {
    my($self, $pos, $bNetToHost) = @_;
    my $buf = substr($self->{sbuffer}, $pos + 4, $self->GetAtomSize($pos) - 8);
    return ($bNetToHost) ? pack('L*', unpack 'N*', $buf) : $buf; 
}

sub Decrypt {
    my($self, $cipherText, $offset, $count, $alg) = @_;
    my $len = int($count / 16) * 16;
    substr( $$cipherText, $offset, $len, 
      $alg->decrypt(substr($$cipherText, $offset, $len)) );
}

sub GetUserKey {
    my($self, $userID, $keyID) = @_;
    my ($userKey, $strFile, $fh);
    $strFile = sprintf("%s%s%sdrms%s%08X.%03d", $self->{strHome}, 
      $self->{dirSep}, $self->{sPfix}, $self->{dirSep}, $userID, $keyID);
    open($fh, '<', $strFile) or croak "Cannot open file $strFile: $!";
    binmode $fh;
    read($fh, $userKey, -s $strFile) or croak "Cannot read user keyfile: $!";
    return $userKey;
}

sub GetSampleTable {
    my($self) = @_;
    my $adSTSZ = $self->GetAtomData($self->GetAtomPos($AtomSTSZ), 1);
    my $sampleCount = unpack('L', substr($adSTSZ, 8, 4));
    my @samples = unpack( 'L*', substr($adSTSZ, 12, 12 + ($sampleCount * 4)) );
    return \@samples;
}

sub DeDRMS {
    my ($self, $infile, $outfile) = @_;
    open(my $infh, '<', $infile) or croak "Cannot open $infile: $!";
    binmode $infh;
    read($infh, $self->{sbuffer}, -s $infile) or croak "Cannot get buffer: $!";
    close $infh;
    my $apDRMS = $self->GetAtomPos($AtomDRMS);
    my $apSINF = $self->GetAtomPos($AtomSINF);
    my $apMDAT = $self->GetAtomPos($AtomMDAT);
    my $sampleTable = $self->GetSampleTable();
    my $adUSER = $self->GetAtomData( $self->GetAtomPos($AtomUSER), 1 );
    my $adKEY  = $self->GetAtomData( $self->GetAtomPos($AtomKEY ), 1 );
    my $adIVIV = $self->GetAtomData( $self->GetAtomPos($AtomIVIV), 0 );
    my $adNAME = $self->GetAtomData( $self->GetAtomPos($AtomNAME), 0 );
    my $adPRIV = $self->GetAtomData( $self->GetAtomPos($AtomPRIV), 0 );
    my $userID  = unpack('L', $adUSER);
    my $keyID   = unpack('L', $adKEY );
    my $strNAME = unpack('a', $adNAME);
    my $userKey = $self->GetUserKey($userID, $keyID);
    my $md5Hash = new Digest::MD5;
    $md5Hash->add( substr($adNAME, 0, index($adNAME, "\0")), $adIVIV );
    my $alg = new Crypt::Rijndael($userKey, Crypt::Rijndael::MODE_CBC);
    $alg->set_iv($md5Hash->digest);
    $self->Decrypt(\$adPRIV, 0, length($adPRIV), $alg);
    unless($adPRIV =~ /^itun/) { croak "Decryption of 'priv' atom failed." }
    my $key = substr($adPRIV, 24, 16);
    $alg = new Crypt::Rijndael($key, Crypt::Rijndael::MODE_CBC);
    $alg->set_iv( substr($adPRIV, 48, 16) );
    my $posit = $apMDAT + 4;
    foreach my $samplesize (@{$sampleTable}) {
        $self->Decrypt(\$self->{sbuffer}, $posit, $samplesize, $alg);
        $posit += $samplesize;
    }
    substr($self->{sbuffer}, $apDRMS, length($AtomMP4A), $AtomMP4A);
    substr($self->{sbuffer}, $apSINF, length($AtomSINF), uc $AtomSINF);
    $self->{sbuffer} =~ s/geID/xxID/;
    open(my $outfh, '>', $outfile) or croak "Cannot write to $outfile: $!";
    binmode $outfh;
    print $outfh $self->{sbuffer};
}

# DeDRMS is aliased to DecryptFile
sub DecryptFile { DeDRMS(@_) }

=head1 NAME

Audio::M4pDecrypt -- DRMS decryption of Apple iTunes style MP4 player files

=head1 DESCRIPTION
    
Perl port of the DeDRMS.cs program by Jon Lech Johansen

=head1 SYNOPSIS

    use Audio::M4pDecrypt;

    my $outfile = 'mydecodedfile';
    my $deDRMS = new Audio::M4pDecrypt;
    $deDRMS->DeDRMS($mp4file, $outfile);

    See also the M4pDecrypt.pl example program in this distribution.

=head1 METHODS

=over 4

=item B<new>

my $cs = new Audio::M4pDecrypt;

my $cs_conparam = Audio::M4pDecrypt->new(
  strHome => '/winroot/Documents and Settings/administrator/Application Data',
  sPfix => '.', 
  dirSep => '/'
);

Optional arguments: strHome is the directory containing the keyfile directory.
After running VLC on a .m4p file under Windows, MacOS X, and Linux, this should
be found by the module automatically (APPDATA dir under Win32, ~/ under OS X and 
Linux). sPfix is '.' for MacOS/*nix, nil with Windows. dirSep is the char that 
separates directories, often /.

=item B<DeDRMS>

my $cs = new Audio::M4pDecrypt;
$cs->DeDRMS('infilename', 'outfilename');

Decode infilename, write to outfilename. Reading slurps up an entire file,
so output can overwrite the same file without a problem, we hope. Backup first.

=item B<DecryptFile>

$cs->DecryptFile('infilename', 'outfilename');

More descriptive alias for the B<DeDRMS> method.

=back

=item B<NOTES>

    From Jon Lech Johansen:

        DeDRMS requires that you already have the user key file(s) for
        your files. The user key file(s) can be generated by playing
        your files with the VideoLAN Client [1][2].

        DeDRMS does not remove the UserID, name and email address.
        The purpose of DeDRMS is to enable Fair Use, not facilitate
        copyright infringement.

    [1] http://www.videolan.org/vlc/ [videolan.org]
    [2] http://wiki.videolan.org/tiki-read_article.php?articleId=5 [videolan.org]


=head1 AUTHOR

    Original C# version: Jon Lech Johansen <jon-vl@nanocrew.net>
    Perl version: William Herrera (wherrera@skylightview.com).

=head1 SUPPORT

Questions, feature requests and bug reports should go to wherrera@skylightview.com

=head1 COPYRIGHT

 /*****************************************************************************
 * DeDRMS.cs: DeDRMS 0.1
 *****************************************************************************
 * Copyright (C) 2004 Jon Lech Johansen <jon-vl@nanocrew.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111, USA.
 *****************************************************************************/

=over 4

Perl translation with portability modifications Copyright (C) 2004,
by William Herrera. Any and all of Perl code modifications of the original 
also are under GPL copyright.

=back

=cut

1;
