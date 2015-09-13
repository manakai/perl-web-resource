package Test::Certificates;
use strict;
use warnings;
use Path::Tiny;

my $root_path = path (__FILE__)->parent->parent->parent->parent->absolute;
my $cert_path = $root_path->child ('local/cert');
my $cn = $ENV{SERVER_HOST_NAME} // 'hoge.test';

sub ca_path ($$) {
  return $cert_path->child ('ca-' . $_[1]);
} # ca_path

sub cert_path ($$) {
  return $cert_path->child ($cn . '-' . $_[1]);
} # cert_path

sub wait_create_cert ($) {
  if ($_[0]->ca_path ('cert.pem')->stat->mtime + 60*60*24 < time) {
    system "rm \Q$cert_path\E/*.pem";
  }
  unless ($_[0]->cert_path ('key-pkcs1.pem')->is_file) {
    system $root_path->child ('perl'), $root_path->child ('t_deps/bin/generate-certs-for-tests.pl'), $cert_path, $cn;
    sleep 2;
  }
} # wait_create_cert

1;
