package Test::Certificates;
use strict;
use warnings;
use Path::Tiny;

my $root_path = path (__FILE__)->parent->parent->parent->parent->absolute;
my $cert_path = $root_path->child ('local/cert2');
my $cn = $ENV{SERVER_HOST_NAME} // 'hoge.test';
$cert_path->mkpath;

#my $gen_path = $root_path->child ('t_deps/bin/generate-certs-for-tests.pl');
my $gen_path = $root_path->child ('t_deps/bin/generate-certs-for-tests-ec.pl');

sub ca_path ($$) {
  return $cert_path->child ('ca-' . $_[1]);
} # ca_path

sub cert_path ($$;%) {
  my (undef, undef, %args) = @_;
  return $cert_path->child (($args{host} || $cn) . '-' . $_[1]);
} # cert_path

sub cert_name ($) {
  return $cn;
} # cert_name

sub wait_create_cert ($;%) {
  my (undef, %args) = @_;
  if ($ENV{RECREATE_CERTS} or
      ($_[0]->ca_path ('cert.pem')->is_file and
       $_[0]->ca_path ('cert.pem')->stat->mtime + 60*60*24 < time)) {
    system "rm \Q$cert_path\E/*.pem";
  }
  my $cert_pem_path = $_[0]->cert_path ('cert.pem', host => $args{host});
  system $root_path->child ('perl'), $gen_path, $cert_path, $args{host} || $cn
      unless $cert_pem_path->is_file;

  require Net::SSLeay;
  require Web::DateTime::Parser;

  my $bio = Net::SSLeay::BIO_new (Net::SSLeay::BIO_s_mem ());
  my $rv = Net::SSLeay::BIO_write ($bio, $cert_pem_path->slurp);
  my $x509 = Net::SSLeay::PEM_read_bio_X509 ($bio);
  Net::SSLeay::BIO_free ($bio);
  die "Failed to parse |$cert_pem_path|" unless $x509;

  my $parser = Web::DateTime::Parser->new;
  my $dt = $parser->parse_global_date_and_time_string
      (Net::SSLeay::P_ASN1_TIME_get_isotime
           (Net::SSLeay::X509_get_notBefore ($x509)));
  my $tt = $dt->to_unix_number;

  my $delta = $tt - time;
  if ($delta > 0) {
    warn "Wait $delta seconds...\n";
    sleep $delta;
  }
  Net::SSLeay::X509_free($x509);
} # wait_create_cert

1;
