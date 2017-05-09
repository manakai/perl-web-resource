use strict;
use warnings;
use Path::Tiny;

my $file = shift or die;

my $data = substr path ($file)->slurp, 0, 200;
my $ascii = $data;

$data =~ s/(.)/sprintf '\\x%02X', ord $1/ges;

$ascii =~ s/[^\x20-\x7E]/_/g;

warn $ascii, "\n";
warn "\n";

print $data;
