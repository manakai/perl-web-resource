package Web::Transport::RequestConstructor;
use strict;
use warnings;
our $VERSION = '1.0';
use Carp;
use Web::Encoding qw(encode_web_utf8);
use Web::URL::Canonicalize qw(url_to_canon_url parse_url serialize_parsed_url);

sub percent_encode_c ($) {
  my $s = encode_web_utf8 $_[0];
  $s =~ s/([^0-9A-Za-z._~-])/sprintf '%%%02X', ord $1/ge;
  return $s;
} # percent_encode_c

sub serialize_form_urlencoded ($) {
  my $params = shift || {};
  return join '&', map {
    my $n = percent_encode_c $_;
    my $vs = $params->{$_};
    if (defined $vs and ref $vs eq 'ARRAY') {
      (map { $n . '=' . percent_encode_c $_ } grep { defined $_ } @$vs);
    } elsif (defined $vs) {
      ($n . '=' . percent_encode_c $vs);
    } else {
      ();
    }
  } sort { $a cmp $b } keys %$params;
} # serialize_form_urlencoded

my $QueryMethods = { # XXX
  GET => 1, HEAD => 1, DELETE => 1,
};

sub create ($$$) {
  my (undef, $url, $args) = @_;

  my $method = encode_web_utf8
      (defined $args->{method} ? $args->{method} : 'GET');

  my $headers = $args->{headers} || {};
  my $header_list = [];
  my $has_header = {};
  for my $name (keys %$headers) {
    if (defined $headers->{$name}) {
      if (ref $headers->{$name} eq 'ARRAY') {
        push @$header_list, map {
          [(encode_web_utf8 $name), (encode_web_utf8 $_)]
        } @{$headers->{$name}};
      } else {
        push @$header_list,
            [(encode_web_utf8 $name), (encode_web_utf8 $headers->{$name})];
      }
    }
    my $name_lc = $name;
    $name_lc =~ tr/A-Z/a-z/; ## ASCII case-insensitive
    $has_header->{$name_lc} = 1;
  }

  if (defined $args->{params}) {
    if ($QueryMethods->{$method} or defined $args->{body}) {
      # XXX if $url has query or fragment
      $url .= '?' . serialize_form_urlencoded $args->{params};
    } else {
      unless ($has_header->{'content-type'}) {
        push @$header_list, ['Content-Type', 'application/x-www-form-urlencoded'];
      }
      $args->{body} = serialize_form_urlencoded $args->{params};
    }
  }

  push @$header_list, ['Accept', '*/*'] unless $has_header->{'accept'};
  push @$header_list, ['Accept-Language', 'en'] unless $has_header->{'accept-language'};
  push @$header_list, ['User-Agent', 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.87 Safari/537.36'] unless $has_header->{'user-agent'};

  if (defined $args->{body}) {
    push @$header_list, ['Content-Length', length ($args->{body})];
  }
  # XXX or, method requires payload

  # XXX Cookie
  # XXX basic auth
  # XXX OAuth1

  if (defined $args->{bearer}) {
    push @$header_list, ['Authorization' => 'Bearer ' . encode_web_utf8 $args->{bearer}];
    $has_header->{authorization} = 1;
  }

  if ($args->{basic_auth}) {
    require MIME::Base64;
    my $auth = MIME::Base64::encode_base64
        (encode_web_utf8 ((defined $args->{basic_auth}->[0] ? $args->{basic_auth}->[0] : '') . ':' .
                          (defined $args->{basic_auth}->[1] ? $args->{basic_auth}->[1] : '')), '');
    push @$header_list, ['Authorization', 'Basic ' . $auth];
    $has_header->{authorization} = 1;
  }

  if ($args->{superreload} or
      defined $has_header->{cookie} or
      defined $has_header->{authorization} or
      defined $has_header->{'x-wsse'}) {
    push @$header_list, ['Pragma', 'no-cache'], ['Cache-Control', 'no-cache'];
  }

  # XXX Accept-Encoding

  for (@$header_list) {
    $_->[1] =~ tr/\x0D\x0A/\x20\x20/;
  }

  my $url_record = parse_url url_to_canon_url $url, 'about:blank';

  return ($method, $url_record, $header_list, defined $args->{body} ? \($args->{body}) : undef);
} # create

1;

=head1 LICENSE

Copyright 2009-2013 Hatena <https://www.hatena.ne.jp/>.

Copyright 2014-2016 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
