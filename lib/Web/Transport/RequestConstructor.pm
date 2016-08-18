package Web::Transport::RequestConstructor;
use strict;
use warnings;
our $VERSION = '1.0';
require utf8;
use Carp;
use Web::Encoding qw(encode_web_utf8);
use Web::URL::Encoding qw(serialize_form_urlencoded percent_encode_c);

use constant DEBUG => $ENV{WEBUA_DEBUG} || 0;

my @BoundaryAlphabet = ('a'..'z', '0'..'9');

sub _fde ($) {
  my $s = encode_web_utf8 $_[0];
  $s =~ s/([\x00-\x1F\x22\x25\x5C\x7F])/sprintf '%%%02X', ord $1/ge;
  return $s;
} # _fde

sub create ($$) {
  my (undef, $args) = @_;

  my $url_record;
  if (defined $args->{url}) {
    $url_record = $args->{url};
  } elsif (defined $args->{base_url}) {
    if (defined $args->{path}) {
      require Web::URL;
      my $prefix = '/';
      if (defined $args->{path_prefix}) {
        $prefix = Web::URL->parse_string ($args->{path_prefix}, Web::URL->parse_string (q<https://base/>));
        if (defined $prefix and $prefix->get_origin->to_ascii eq q<https://base>) {
          $prefix = $prefix->path;
          $prefix .= '/' unless $prefix =~ m{/\z};
        } else {
          return {failed => 1, message => "Bad |path_prefix|: |$args->{path_prefix}|"};
        }
      }
      $url_record = Web::URL->parse_string
          (($prefix . join '/', map { percent_encode_c $_ } @{$args->{path}}),
           $args->{base_url});
    }
  }
  return {failed => 1, message => "No |url| argument"}
      unless defined $url_record;

  my $method = encode_web_utf8
      (defined $args->{method} ? $args->{method} : 'GET');

  my $headers = $args->{headers} || {};
  my $header_list = [];
  my $has_header = {};
  my $ct;
  my $auth;
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
    if ($name_lc eq 'content-type') {
      $ct = $header_list->[-1]->[-1];
    } elsif ($name_lc eq 'authorization') {
      $auth = $header_list->[-1]->[-1];
    }
  }

  if (defined $args->{cookies}) {
    push @$header_list,
        ['Cookie', join '; ', map {
          if (defined $args->{cookies}->{$_}) {
            (percent_encode_c $_) . '=' . (percent_encode_c $args->{cookies}->{$_});
          } else {
            ();
          }
        } sort { $a cmp $b } keys %{$args->{cookies}}];
    pop @$header_list unless length $header_list->[-1]->[1];
    $has_header->{cookie} = 1;
  }

  my $boundary;
  if (defined $args->{files} and not defined $args->{body} and not defined $ct) {
    $boundary = '';
    $boundary .= $BoundaryAlphabet[rand @BoundaryAlphabet] for 1..50;
    push @$header_list, ['Content-Type', $ct = 'multipart/form-data; boundary=' . $boundary];
    $has_header->{'content-type'} = 1;
  }
  croak "Both |files| and |body| are specified"
      if not defined $boundary and keys %{$args->{files} or {}};
  if (defined $boundary) {
    ## Unfortunately the multipart/form-data encoding is not well
    ## defined and what browsers do is disaster...

    my @part;

    for my $key (keys %{$args->{params} or {}}) {
      next unless defined $args->{params}->{$key};
      for my $value (ref $args->{params}->{$key} eq 'ARRAY'
                         ? @{$args->{params}->{$key}}
                         : ($args->{params}->{$key})) {
        push @part, 
            'Content-Disposition: form-data; name="'._fde ($key).'"' . "\x0D\x0A" .
            "\x0D\x0A" . 
            (encode_web_utf8 $value);
      }
    }

    for my $key (keys %{$args->{files} or {}}) {
      next unless defined $args->{files}->{$key};
      for my $value (ref $args->{files}->{$key} eq 'ARRAY'
                         ? @{$args->{files}->{$key}}
                         : ($args->{files}->{$key})) {
        my $mime = defined $value->{mime_type} ? $value->{mime_type} : 'application/octet-stream';
        my $file_name = defined $value->{mime_filename} ? $value->{mime_filename} : '';
        croak "File's |body_ref|'s value is utf8-flagged"
            if utf8::is_utf8 (${$value->{body_ref}});
        push @part, 
            "Content-Type: "._fde ($mime)."\x0D\x0A" .
            'Content-Disposition: form-data; name="'._fde ($key).'"; filename="'._fde ($file_name).'"' . "\x0D\x0A" .
            "\x0D\x0A" .
            ${$value->{body_ref}};
      }
    }

    $args->{body} = "--$boundary\x0D\x0A" .
        join "\x0D\x0A--$boundary\x0D\x0A", @part if @part;
    $args->{body} .= "\x0D\x0A--$boundary--\x0D\x0A";
  }

  my $param_container = (
    $method eq 'POST' and
    ((not defined $ct and not defined $args->{body}) or
     (defined $ct and $ct eq 'application/x-www-form-urlencoded'))
  ) ? 'body' : 'query';
  if (not defined $boundary and defined $args->{params}) {
    if ($param_container eq 'query') {
      $url_record = $url_record->clone;
      $url_record->set_query_params ($args->{params}, append => 1);
    } else { # $param_container eq 'body'
      unless ($has_header->{'content-type'}) {
        push @$header_list, ['Content-Type', $ct = 'application/x-www-form-urlencoded'];
        $has_header->{'content-type'} = 1;
      }
      $args->{body} = serialize_form_urlencoded $args->{params};
    }
  }

  push @$header_list, ['Accept', '*/*'] unless $has_header->{'accept'};
  push @$header_list, ['Accept-Language', 'en'] unless $has_header->{'accept-language'};
  push @$header_list, ['User-Agent', 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.87 Safari/537.36'] unless $has_header->{'user-agent'};

  if (defined $args->{bearer}) {
    push @$header_list, ['Authorization' => $auth = 'Bearer ' . encode_web_utf8 $args->{bearer}];
    $has_header->{authorization} = 1;
  }

  if ($args->{basic_auth}) {
    require MIME::Base64;
    my $bauth = MIME::Base64::encode_base64
        (encode_web_utf8 ((defined $args->{basic_auth}->[0] ? $args->{basic_auth}->[0] : '') . ':' .
                          (defined $args->{basic_auth}->[1] ? $args->{basic_auth}->[1] : '')), '');
    push @$header_list, ['Authorization', $auth = 'Basic ' . $bauth];
    $has_header->{authorization} = 1;
  }

  my $nostore = 0;
  if (defined $args->{oauth1}) {
    my $container = $args->{oauth1_container};
    if (not defined $container) {
      $container = $param_container if defined $auth;
    }

    require Web::Transport::OAuth1;
    my $result = Web::Transport::OAuth1->authenticate
        (request_method => $method,
         url => $url_record, # might be mutated
         http_authorization => undef,
         body_ref => (defined $args->{body} ? \($args->{body}) : undef),
         container => $container,
         oauth_consumer_key => $args->{oauth1}->[0],
         oauth_callback => $args->{oauth_callback},
         client_shared_secret => $args->{oauth1}->[1],
         oauth_token => $args->{oauth1}->[2],
         token_shared_secret => $args->{oauth1}->[3],
         oauth_verifier => $args->{oauth_verifier});
    if (DEBUG > 1) {
      warn sprintf "%s: OAuth1 signature base string: %s\n",
          $args->{debug_prefix}, $result->{signature_base_string};
    }
    if (defined $result->{http_authorization}) {
      push @$header_list, ['Authorization', $auth = $result->{http_authorization}];
      $has_header->{authorization} = 1;
    }
    if (defined $result->{body_appended} and
        length $result->{body_appended}) {
      if (not defined $ct) {
        push @$header_list, ['Content-Type', $ct = 'application/x-www-form-urlencoded'];
        $has_header->{'content-type'} = 1;
      }
      $args->{body} .= $result->{body_appended};
    }
    $nostore = 1;
  }

  if (defined $args->{body}) {
    push @$header_list, ['Content-Length', length ($args->{body})];
  }
  # XXX or, method requires payload

  if ($args->{superreload}) {
    push @$header_list, ['Pragma', 'no-cache'], ['Cache-Control', 'no-cache'];
  }
  $nostore = 1 if
      defined $has_header->{cookie} or
      defined $has_header->{authorization} or
      defined $has_header->{'x-wsse'};
  if ($nostore) {
    push @$header_list, ['Pragma', 'no-cache'] unless $args->{superreload};
    push @$header_list, ['Cache-Control', 'no-store'];
  }

  # XXX Accept-Encoding

  for (@$header_list) {
    $_->[1] =~ tr/\x0D\x0A/\x20\x20/;
  }

  return ($method, $url_record, $header_list, defined $args->{body} ? \($args->{body}) : undef);
} # create

1;

=head1 HISTORY

The module partially derived from L<Web::UserAgent::Functions> from
<https://github.com/wakaba/perl-web-useragent-functions>.

=head1 LICENSE

Copyright 2009-2013 Hatena <https://www.hatena.ne.jp/>.

Copyright 2014-2016 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut