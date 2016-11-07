package Web::Transport::OAuth1;
use strict;
use warnings;
our $VERSION = '3.0';
use Carp qw(croak);
use Digest::SHA;
use MIME::Base64;
use Web::URL::Encoding qw(oauth1_percent_encode_c oauth1_percent_encode_b);

sub create_request_params ($$$$) {
  my ($query, $header, $bodyref, $params) = @_;

  # 3.4.1.3.1.
  my @param;

  push @param, map { [map {
    s/\+/ /; s/%([0-9A-Fa-f]{2})/pack 'C', hex $1/ge; $_;
  } split /=/, $_, 2] } split /&/, $query, -1 if defined $query;

  if (defined $header and
      $header =~ s/^[Oo][Aa][Uu][Tt][Hh][\x09\x0A\x0D\x20]+//) {
    while ($header =~ s/^([^=\x09\x0A\x0D\x20]+)="([^\\"]*)"(?:,[\x09\x0A\x0D\x20]*)?//) {
      my ($n, $v) = ($1, $2);
      next if $n =~ /\A[Rr][Ee][Aa][Ll][Mm]\z/;
      $n =~ s/%([0-9A-Fa-f]{2})/pack 'C', hex $1/ge;
      $v =~ s/%([0-9A-Fa-f]{2})/pack 'C', hex $1/ge;
      push @param, [$n => $v];
    }
  }

  push @param, map {
    [map {
      s/\+/ /; s/%([0-9A-Fa-f]{2})/pack 'C', hex $1/ge; $_;
    } split /=/, $_, 2];
  } split /&/, $$bodyref, -1 if defined $bodyref;

  # and @$params

  # 3.4.1.3.2.

  # 1.
  for (@param) {
    $_ = [oauth1_percent_encode_c $_->[0],
          defined $_->[1] ? oauth1_percent_encode_c $_->[1] : ''];
  }
  for (@$params) {
    push @param, [oauth1_percent_encode_c $_->[0],
                  defined $_->[1] ? oauth1_percent_encode_c $_->[1] : ''];
  }

  # 4.
  return join '&',

      # 3.
      map { $_->[0] . '=' . $_->[1] }

      # 2.
      sort { $a->[0] cmp $b->[0] || $a->[1] cmp $b->[1] } @param;
} # create_request_params

# 3.4.1.1.
sub create_signature_base_string ($$$$$$) {
  my ($method, $url, $authorization, $bodyref, $params, $result) = @_;
  my $string = '';

  # 1.
  $method =~ tr/a-z/A-Z/;
  $string .= oauth1_percent_encode_c $method;

  # 2.
  $string .= '&';

  # 3. (3.4.1.2. base string URL)
  $string .= oauth1_percent_encode_c $url->originpathquery;

  # 4.
  $string .= '&';

  # 5.
  $string .= oauth1_percent_encode_c create_request_params
      ($url->query, $authorization, $bodyref, $params);

  $result->{signature_base_string} = $string;
} # create_signature_base_string

sub create_hmac_sha1_key ($$) {
  my ($client_secret, $token_secret) = @_;

  # 1.
  croak '|client_shared_secret| is not set' unless defined $client_secret;
  my $s = oauth1_percent_encode_c $client_secret;

  # 2.
  $s .= '&';

  # 3.
  croak '|token_shared_secret| is not set' unless defined $token_secret;
  $s .= oauth1_percent_encode_c $token_secret;

  return $s;
} # create_hmac_sha1_key

# 3.5.
sub append_oauth_params ($$$$$) {
  my ($container, $params, $url, $bodyref, $result) = @_;

  if ($container eq 'authorization') {
    my $header = 'OAuth ';
    $header .= ($header =~ /=/ ? ', ' : '')
            . join ', ',
                ($header =~ /\brealm="/ ? () : ('realm=""')),
                map { (oauth1_percent_encode_c $_->[0]) . '="' . (oauth1_percent_encode_c $_->[1]) . '"' }
                    @$params,
                    [oauth_signature => $result->{oauth_signature}];
    $result->{http_authorization} = $header;
  } elsif ($container eq 'query') {
    $url->set_query_params ({
      oauth_signature => $result->{oauth_signature},
      map { $_->[0] => $_->[1] } @$params
    }, append => 1);
  } elsif ($container eq 'body') {
    $result->{body_appended} = '';
    $result->{body_appended} .= '&' if defined $bodyref and length $$bodyref;
    $result->{body_appended} .= join '&',
        map { (oauth1_percent_encode_c $_->[0]) . '=' . (oauth1_percent_encode_c $_->[1]) }
                @$params,
                [oauth_signature => $result->{oauth_signature}];
  } else {
    croak "Unknown parameter container |$container|";
  }
} # append_oauth_params

my @NonceAlphabet = ('A'..'Z', 'a'..'z', '0'..'9');

# 3.
sub authenticate ($%) {
  my (undef, %args) = @_;

  $args{oauth_timestamp} = time unless defined $args{oauth_timestamp};
  $args{oauth_nonce} = '';
  $args{oauth_nonce} .= $NonceAlphabet[rand @NonceAlphabet] for 0..30+rand 14;
  $args{oauth_signature_method} = 'HMAC-SHA1';
  $args{oauth_version} = '1.0';

  my @param;
  for my $key (qw(oauth_consumer_key oauth_signature_method
                  oauth_timestamp oauth_nonce oauth_version)) {
    croak "|$key| is not set" unless defined $args{$key};
    push @param, [$key => $args{$key}];
  }
  for my $key (qw(oauth_callback oauth_token oauth_verifier)) {
    push @param, [$key => $args{$key}] if defined $args{$key};
  }

  my $result = {};
  croak "|request_method| is not set" unless defined $args{request_method};
  croak "|url| is not set" unless defined $args{url};
  create_signature_base_string
      ($args{request_method}, $args{url},
       $args{http_authorization}, $args{body_ref}, \@param,
       $result);

  # 3.4.2.
  my $key = create_hmac_sha1_key
      ($args{client_shared_secret}, $args{token_shared_secret});
  $result->{oauth_signature} = MIME::Base64::encode_base64
      (Digest::SHA::hmac_sha1 ($result->{signature_base_string}, $key), '');

  append_oauth_params ($args{container} || 'authorization', \@param,
                       $args{url}, $args{body_ref}, $result);

  return $result;
} # authenticate

1;

__END__

Input parameters MUST be byte strings, conforming to HTTP and/or OAuth
(RFC 5849) specifications.

$result = authenticate_by_oauth1 (
  request_method => $string,
  url => $url_record,
  http_authorization => $bytes, # or undef
  body_ref => \$bytes, # or undef
  container => undef, # 'authorization' (default) or 'query' or 'body'
  oauth_consumer_key => $string,
  client_shared_secret => $string,
  oauth_token => $string, # or undef
  token_shared_secret => $string,
  oauth_callback => $string, # or undef
  oauth_verifier => $string, # or undef
);

warn "Signature base string: " . $result->{signature_base_string} . "\n";
warn "Request URL: " . $url->stringify . "\n";
warn "Authorization: " . ($result->{http_authorization} // '') . "\n";
warn "Body appended: " . $result->{body_appended} . "\n";

The module partially derived from L<Web::UserAgent::OAuth> from
<https://github.com/wakaba/perl-web-useragent-functions>.

Copyright 2009-2013 Hatena <https://www.hatena.ne.jp/>.

Copyright 2014-2016 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.
