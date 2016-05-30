package Test::Certificates;
use strict;
use warnings;
use Path::Tiny;
use File::Temp;

my $root_path = path (__FILE__)->parent->parent->parent->parent->absolute;
my $cert_path = $root_path->child ('local/cert');
my $cn = $ENV{SERVER_HOST_NAME} // 'hoge.test';
$cert_path->mkpath;

#my $gen_path = $root_path->child ('t_deps/bin/generate-certs-for-tests.pl');
my $gen_path = $root_path->child ('t_deps/bin/generate-certs-for-tests-ec.pl');

sub ca_path ($$) {
  return $cert_path->child ('ca-' . $_[1]);
} # ca_path

sub escape ($) {
  my $s = $_[0];
  $s =~ s/([^0-9a-z])/sprintf '_%02X', ord $1/ge;
  return $s;
} # escape

sub cert_path ($$;%) {
  my (undef, undef, %args) = @_;
  return $cert_path->child (escape ($args{host} || $cn) . '-' . ($args{no_san} ? 'nosan-' : '')
      . (defined $args{cn} ? 'cn-' . (escape $args{cn}) . '-' : '')
      . (defined $args{cn2} ? 'cn2-' . (escape $args{cn2}) . '-' : '')
      . $_[1]);
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
  my $cert_pem_path = $_[0]->cert_path ('cert.pem', host => $args{host}, no_san => $args{no_san}, cn => $args{cn}, cn2 => $args{cn2});
  unless ($cert_pem_path->is_file) {
    local $ENV{CERT_NO_SAN} = !!$args{no_san};
    local $ENV{CERT_CN} = $args{cn} // '';
    local $ENV{CERT_CN2} = $args{cn2} // '';
    system $root_path->child ('perl'), $gen_path, $cert_path, $args{host} || $cn;
  }

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

sub ocsp_response ($%) {
  my ($class, %args) = @_;

  my $cert_path = $class->cert_path ('cert.pem', host => $args{host}, no_san => $args{no_san}, cn => $args{cn}, cn2 => $args{cn2});

  my $bio = Net::SSLeay::BIO_new (Net::SSLeay::BIO_s_mem ());
  my $rv = Net::SSLeay::BIO_write ($bio, $cert_path->slurp);
  my $x509 = Net::SSLeay::PEM_read_bio_X509 ($bio);
  Net::SSLeay::BIO_free ($bio);
  die "Failed to parse |$cert_path|" unless $x509;
  my $sn = Net::SSLeay::X509_get_subject_name ($x509);
  my $subj = Net::SSLeay::X509_NAME_print_ex ($sn, Net::SSLeay::XN_FLAG_RFC2253 (), 0);
  my $sno = Net::SSLeay::P_ASN1_INTEGER_get_hex (Net::SSLeay::X509_get_serialNumber ($x509));
  Net::SSLeay::X509_free($x509);

  my $index_file = File::Temp->new;
  my $index_path = path ($index_file->filename);

  my $status = 'V';
  my $rdate = '';
  my $xdate = '';
  if ($args{revoked}) {
    $status = 'R';
    $rdate = '160101000000Z';
  }
  if ($args{expired}) {
    $xdate = '150101000000Z';
    $status = 'E';
  }

  my $index = [];
  push @$index, join "\t", $status, $xdate, $rdate, $sno, 'unknown', $subj;
  $index_path->spew ((join "\n", @$index) . "\n");

  my $res_file = File::Temp->new;
  my $res_path = path ($res_file->filename);
  
  (system 'openssl', 'ocsp',
       '-index' => $index_path,
       '-CA' => $class->ca_path ('cert.pem'),
       '-rkey' => $class->ca_path ('key.pem'),
       '-rsigner' => $class->ca_path ('cert.pem'),
       '-issuer' => $class->ca_path ('cert.pem'),
       '-cert' => $cert_path,
       ($args{no_next} ? () : ('-ndays' => 100)),
       #'-text', # DEBUG
       '-respout' => $res_path) == 0
      or die $?;

  return $res_path->slurp; # DER encoded
} # ocsp_response

1;
