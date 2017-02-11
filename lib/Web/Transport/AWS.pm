package Web::Transport::AWS;
use strict;
use warnings;
our $VERSION = '1.0';
use Digest::SHA qw(sha256_hex hmac_sha256 hmac_sha256_hex);
use Web::Encoding;

sub reescape ($) {
  my $s = $_[0];
  $s =~ s/%([0-9A-Fa-f]{2})/pack 'C', hex $1/ge;
  $s =~ s/([^\x2D-.0-9A-Z_a-z~])/sprintf '%%%02X', ord $1/ge;
  return $s;
} # reescape

## clock
## body_ref
## header_list    mutated by this method
## signed_headers
## method
## url
## region
## service
## access_key_id
## secret_access_key
sub aws4 ($%) {
  my (undef, %args) = @_;

  ## <https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html>
  my $time = int $args{clock}->();
  my @time = gmtime $time;
  my $amz_date = sprintf '%04d%02d%02dT%02d%02d%02dZ',
      $time[5]+1900, $time[4]+1, @time[3, 2, 1, 0];
  my $ymd = sprintf '%04d%02d%02d', $time[5]+1900, $time[4]+1, $time[3];

  if (utf8::is_utf8 (${$args{body_ref}})) {
    ## An error will be thrown later.
    return;
  }
  my $body_sha256 = sha256_hex (${$args{body_ref}});

  push @{$args{header_list}},
      ['x-amz-date' => $amz_date, 'x-amz-date'],
      ['x-amz-content-sha256' => $body_sha256, 'x-amz-content-sha256'];

  my $to_be_signed = {'content-type' => 1, 'host' => 1};
  for (keys %{$args{signed_headers} or {}}) {
    if ($args{signed_headers}->{$_}) {
      my $v = $_;
      $v =~ tr/A-Z/a-z/;
      $to_be_signed->{$v} = 1;
    }
  }
  my @signed_headers = (['host', $args{url}->hostport, 'host']);
  for (@{$args{header_list}}) {
    if ($to_be_signed->{$_->[2]} or $_->[2] =~ /\Ax-amz-/) {
      if ($_->[1] =~ /\A[\x09\x20]/ or $_->[1] =~ /[\x09\x20]\z/) {
        my $v = $_->[1];
        $v =~ s/\A[\x09\x0A\x0D\x20]+//;
        $v =~ s/[\x09\x0A\x0D\x20]+\z//;
        push @signed_headers, [undef, $v, $_->[2]];
      } else {
        push @signed_headers, $_;
      }
    }
  }
  @signed_headers = sort { $a->[2] cmp $b->[2] } @signed_headers;
  my $signed_headers = join ';', map { $_->[2] } @signed_headers;

  my $query = encode_web_utf8 $args{url}->query;
  $query = join "&", map {
    reescape ($_->[0]) . '=' . reescape (defined $_->[1] ? $_->[1] : '');
  } sort {
    $a->[0] cmp $b->[0];
  } map {
    [split /=/, $_, 2];
  } split m{&}, (defined $query ? $query : ''), -1;

  my $canonical_request = encode_web_utf8 join "\x0A",
      $args{method},
      $args{url}->path,
      $query,
      (map { $_->[2] . ':' . $_->[1] } @signed_headers),
      '',
      $signed_headers,
      $body_sha256;

  my $region = encode_web_utf8 $args{region};
  my $service = encode_web_utf8 $args{service};
  my $scope = join '/', $ymd, $region, $service, 'aws4_request';

  my $string_to_sign = join "\x0A",
      "AWS4-HMAC-SHA256",
      $amz_date,
      $scope,
      sha256_hex ($canonical_request);
  my $date_key = hmac_sha256 ($ymd, 'AWS4' . encode_web_utf8 $args{secret_access_key});
  my $date_region_key = hmac_sha256 ($region, $date_key);
  my $date_region_service_key = hmac_sha256 ($service, $date_region_key);
  my $signing_key = hmac_sha256 ('aws4_request', $date_region_service_key);
  my $signature = hmac_sha256_hex ($string_to_sign, $signing_key);

  #warn $canonical_request;
  #warn $string_to_sign;

  my $authorization = sprintf 'AWS4-HMAC-SHA256 Credential=%s/%s,SignedHeaders=%s,Signature=%s',
      (encode_web_utf8 $args{access_key_id}), $scope, $signed_headers, $signature;
  push @{$args{header_list}},
      ['authorization', $authorization, 'authorization'];
} # aws4

1;
