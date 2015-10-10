use strict;
use warnings;
use Path::Tiny;

sub x ($) {
  system ($_[0]) == 0 or die $?;
} # x

my $path = path (shift or die "Usage: $0 path key-label1 key-label2 ...");
$path->mkpath;

my $ca_name = $ENV{CERT_CA_S} // '/CN=ca.test';
my $ca_key_path = $path->child ('ca-key.pem');
my $ca_cert_path = $path->child ('ca-cert.pem');

unless ($ca_key_path->is_file) {
  x "openssl genrsa -out \Q$ca_key_path\E 2048";

  my $ca_subj = $ca_name;
  x "openssl req -new -x509 -nodes -days 1 -key \Q$ca_key_path\E -out \Q$ca_cert_path\E -subj \Q$ca_subj\E -sha256 -set_serial @{[time]}";

  sleep 1;
}

for my $prefix (@ARGV) {
  my $server_key_path = $path->child ($prefix.'-key.pem');
  my $server_req_path = $path->child ($prefix.'-req.pem');
  my $config_path = $path->child ($prefix.'-openssl.cnf');
  $config_path->spew (
    #path ("/etc/ssl/openssl.cnf")->slurp .
    qq{[san]\nsubjectAltName=DNS:$prefix}
  );
  #my $server_subj = '/';
  #my $server_subj = '/subjectAltName=DNS.1='.$prefix;
  my $server_subj = '/CN='.$prefix;
  x "openssl req -newkey rsa:2048 -days 1 -nodes -keyout \Q$server_key_path\E -out \Q$server_req_path\E -subj \Q$server_subj\E";# -config \Q$config_path\E -reqexts san";

  my $server_key1_path = $path->child ($prefix.'-key-pkcs1.pem');
  x "openssl rsa -in \Q$server_key_path\E -out \Q$server_key1_path\E";

  my $server_cert_path = $path->child ($prefix.'-cert.pem');
  x "openssl x509 -req -in \Q$server_req_path\E -days 1 -CA \Q$ca_cert_path\E -CAkey \Q$ca_key_path\E -out \Q$server_cert_path\E -set_serial @{[time]} -extfile \Q$config_path\E -extensions san";

  my $server_p12_path = $path->child ($prefix.'-keys.p12');
  x "openssl pkcs12 -export -passout pass: -in \Q$server_cert_path\E -inkey \Q$server_key_path\E -out \Q$server_p12_path\E";
}

## License: Public Domain.
