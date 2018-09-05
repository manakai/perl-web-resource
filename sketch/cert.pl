use strict;
use warnings;
use Promise;
use Path::Tiny;
use Web::Transport::PKI::Parser;

my $file_name = shift or die "Usage: perl $0 file";
my $path = path ($file_name);
my $data = $path->slurp;

my $gen = Web::Transport::PKI::Parser->new;

Promise->resolve->then (sub {
  if ($data =~ /-----BEGIN CERTIFICATE-----/) {
    return $gen->parse_pem ($data);
  } else {
    return [$gen->parse_certificate_der ($data)];
  }
})->then (sub {
  my $cert = $_[0]->[0];
  die "Not a certificate" unless defined $cert;
  print $cert->debug_info, "\n";
})->to_cv->recv;
