package Web::Transport::OAuth1;
use strict;
use warnings;
our $VERSION = '4.0';
use Carp qw(croak);
use Digest::SHA;
use Web::URL;
use Web::URL::Encoding qw(oauth1_percent_encode_c oauth1_percent_encode_b
                          percent_decode_c
                          serialize_form_urlencoded);
use Web::DateTime::Clock;
use Web::Transport::Base64;
use Web::Transport::BasicClient;
use Promise;

## Methods of this module is invoked from other modules.  They should
## not be invoked directly by applications.

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
    $_ = [oauth1_percent_encode_b $_->[0],
          defined $_->[1] ? oauth1_percent_encode_b $_->[1] : ''];
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

  $args{oauth_timestamp} = $args{clock}->()
      unless defined $args{oauth_timestamp};
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
  $result->{oauth_signature} = encode_web_base64
      (Digest::SHA::hmac_sha1 ($result->{signature_base_string}, $key));

  append_oauth_params ($args{container} || 'authorization', \@param,
                       $args{url}, $args{body_ref}, $result);

  return $result;
} # authenticate

=pod

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

=cut


## <https://tools.ietf.org/html/rfc5849#section-2.2>
sub _get_auth_url (%) {
  my %args = @_;

  if (not defined $args{url}) {
    $args{url} = ($args{url_scheme} || 'https') . '://' . $args{host} . $args{pathquery};
  }

  $args{url} =~ s/\#.*//s;
  $args{url} .= $args{url} =~ /\?/ ? '&' : '?';

  my $token = $args{temp_token};
  croak '|temp_token| is not specified' unless defined $token;
  $token =~ s/([^0-9A-Za-z._~-])/sprintf '%%%02X', ord $1/ge;

  $args{url} .= 'oauth_token=' . $token;

  return Web::URL->parse_string ($args{url});
} # _get_auth_url

## <https://tools.ietf.org/html/rfc5849#section-2.1>.
sub request_temp_credentials ($%) {
  my ($class, %args) = @_;

  my $scheme = $args{url_scheme} || 'https';
  my $cb = $args{oauth_callback};
  $cb = 'oob' unless defined $cb;

  my $clock = $args{protocol_clock} || Web::DateTime::Clock->realtime_clock;

  my $u = $scheme . '://' . $args{host} . $args{pathquery};
  my $url = Web::URL->parse_string ($u)
      // return Promise->reject ("Bad request URL |$u|");
  my $body = serialize_form_urlencoded ($args{params});

  my $result = $class->authenticate (
    clock => $clock,
    request_method => 'POST',
    url => $url,
    body_ref => \$body,
    oauth_callback => $cb,
    oauth_consumer_key => $args{oauth_consumer_key},
    client_shared_secret => $args{client_shared_secret},
    oauth_token => undef,
    token_shared_secret => '',
    container => 'authorization',
  );

  my ($temp_token, $temp_token_secret, $auth_url);
  my $client = Web::Transport::BasicClient->new_from_url ($url);
  return $client->request (
    method => 'POST',
    url => $url,
    headers => {
      authorization => $result->{http_authorization},
      'content-type' => 'application/x-www-form-urlencoded',
    },
    body => $body,
    last_resort_timeout => $args{timeout},
  )->then (sub {
    my $res = $_[0];
    die $res unless $res->status == 200;
    
    ## Don't check Content-Type for interoperability...
    my %param = map { tr/+/ /; s/%([0-9A-Fa-f]{2})/pack 'C', hex $1/ge; $_ }
                map { (split /=/, $_, 2) } split /&/, $res->body_bytes, -1;
    #unless ($param{oauth_callback_confirmed} eq 'true') {
    #  warn "<@{[$req->uri]}>: |oauth_callback_confirmed| is not |true|\n";
    #}
    die "No |oauth_token| in OAuth1 temporary credentials response"
        unless defined $param{oauth_token};
    die "No |oauth_token_secret| in OAuth1 temporary credentials response"
        unless defined $param{oauth_token_secret};
    my $temp_token = $param{oauth_token};
    my $temp_token_secret = $param{oauth_token_secret};
    my $auth_url = _get_auth_url
        url_scheme => $args{auth}->{url_scheme} // $args{url_scheme},
        host => $args{auth}->{host} // $args{host},
        url => $args{auth}->{url},
        pathquery => $args{auth}->{pathquery},
        temp_token => $temp_token;
    return {
      temp_token => $temp_token,
      temp_token_secret => $temp_token_secret,
      auth_url => $auth_url,
    };
  })->finally (sub {
    return $client->close;
  });
} # request_temp_credentials

## <https://tools.ietf.org/html/rfc5849#section-2.3>.
sub request_token ($%) {
  my ($class, %args) = @_;

  my $clock = $args{protocol_clock} || Web::DateTime::Clock->realtime_clock;
  
  my $scheme = $args{url_scheme} || 'https';
  my $u = $scheme . '://' . $args{host} . $args{pathquery};
  my $url = Web::URL->parse_string ($u);
  my $client = defined $url ? Web::Transport::BasicClient->new_from_url ($url) : undef;

  return Promise->resolve->then (sub {
    die "Bad request URL |$u|" unless defined $url;
    
    die "|temp_token| is not specified" unless defined $args{temp_token};
    if (defined $args{oauth_verifier}) {
      if (defined $args{current_request_oauth_token} and
          $args{current_request_oauth_token} ne $args{temp_token}) {
        die "|current_request_oauth_token| is not equal to |temp_token|";
      }
    } else {
      die "Neither |oauth_verifier| or |current_request_url| is specified"
          unless defined $args{current_request_url};
      my $url = $args{current_request_url};
      $url =~ s/\#.*//s;
      if ($url =~ /\?(.+)/s) {
        my %param = map { tr/+/ /; s/%([0-9A-Fa-f]{2})/pack 'C', hex $1/ge; $_ }
                    map { (split /=/, $_, 2) } split /&/, $1, -1;
        if (not defined $param{oauth_token}) {
          die "|current_request_url| does not have |oauth_token|";
        }
        if ($param{oauth_token} ne $args{temp_token}) {
          die "|current_request_url|'s |oauth_token| is not equal to |temp_token|";
        }
        if (not defined $param{oauth_verifier}) {
          die "|current_request_url| does not have |oauth_verifier|";
        }
        $args{oauth_verifier} = $param{oauth_verifier};
      } else {
        die "|current_request_url| does not have |oauth_token| and |oauth_verifier|";
      }
    }
    
    my $result = $class->authenticate (
      clock => $clock,
      url => $url,
      request_method => 'POST',
      oauth_consumer_key => $args{oauth_consumer_key},
      client_shared_secret => $args{client_shared_secret},
      oauth_token => $args{temp_token},
      token_shared_secret => $args{temp_token_secret},
      oauth_verifier => $args{oauth_verifier},
      container => 'authorization',
    );

    return $client->request (
      method => 'POST',
      url => $url,
      headers => {
        authorization => $result->{http_authorization},
      },
      bytes => '',
      last_resort_timeout => $args{timeout},
    );
  })->then (sub {
    my $res = $_[0];
    die $res unless $res->status == 200;
    
    ## Don't check Content-Type for interoperability...
    my %param = map { tr/+/ /; percent_decode_c $_ }
                map { (split /=/, $_, 2) } split /&/, $res->body_bytes, -1;
    die "No |oauth_token| in OAuth1 token response"
        unless defined $param{oauth_token};
    die "No |oauth_token_secret| in OAuth1 token response"
        unless defined $param{oauth_token_secret};
    my $token = delete $param{oauth_token};
    my $token_secret = delete $param{oauth_token_secret};
    return {
      token => $token,
      token_secret => $token_secret,
      params => \%param,
    };
  })->finally (sub {
    return $client->close;
  });
} # request_token

1;

## Unfortunately this module has no dedicated tests, but there are:
##
##   |t/Web-Transport-BasicClient.t| and
##   |t/Web-Transport-ConnectionClient.t|, which test the |oauth1|
##   request parameter.
##
##   |sketch/oauth-auth-hatena.pl| and |sketch/oauth-auth-twitter.pl|,
##   which manually invoke methods of this module.
##
##   <https://github.com/wakaba/accounts>, which invoke methods of
##   this module and there are tests for integration with OAuth1
##   servers.

=head1 AUTHOR

Wakaba <wakaba@suikawiki.org>.

=head1 HISTORY

This module partially derived from L<Web::UserAgent::OAuth> and
L<Web::UserAgent::Functions::OAuth> in the repository
<https://github.com/wakaba/perl-web-useragent-functions>.

=head1 LICENSE

Copyright 2009-2013 Hatena <https://www.hatena.ne.jp/>.

Copyright 2013-2022 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
