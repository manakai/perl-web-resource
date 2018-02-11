package Web::Transport::RequestConstructor;
use strict;
use warnings;
our $VERSION = '3.0';
use Web::Encoding qw(encode_web_utf8);
use Web::URL::Encoding qw(serialize_form_urlencoded percent_encode_c);
use Web::DateTime;
use Web::DateTime::Clock;
use Web::Transport::TypeError;
use Web::Transport::_Defs;

push our @CARP_NOT, qw(
  ReadableStreamDefaultReader
  ReadableStreamBYOBReader
  Web::Transport::TypeError
);

use constant DEBUG => $ENV{WEBUA_DEBUG} || 0;

my @BoundaryAlphabet = ('a'..'z', '0'..'9');

sub _fde ($) {
  my $s = encode_web_utf8 $_[0];
  $s =~ s/([\x00-\x1F\x22\x25\x5C\x7F])/sprintf '%%%02X', ord $1/ge;
  return $s;
} # _fde

## Interpret a set of request arguments.  See Web::Transport for
## arguements' semantics and syntax.  It returns either a set of
## inputs to request operation or a hash reference representing an
## error, or throws an exception.
sub create ($$) {
  my ($class, $args) = @_;

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
  if ($args->{get_only} and not $method eq 'GET') {
    return {failed => 1, message => "Bad |method| argument |$args->{method}|"};
  }

  my ($header_list, $has_header) = $class->create_header_list
      ($args->{headers}); # or throw
  my $ct;
  my $auth;
  for (@$header_list) {
    if ($_->[2] eq 'content-type') {
      $ct = $_->[1];
    } elsif ($_->[2] eq 'authorization') {
      $auth = $_->[1];
    }
  }

  if (defined $args->{cookies}) {
    push @$header_list,
        ['Cookie', (join '; ', map {
          if (defined $args->{cookies}->{$_}) {
            (percent_encode_c $_) . '=' . (percent_encode_c $args->{cookies}->{$_});
          } else {
            ();
          }
        } sort { $a cmp $b } keys %{$args->{cookies}}), 'cookie'];
    pop @$header_list unless length $header_list->[-1]->[1];
    $has_header->{cookie} = 1;
  }

  my $boundary;
  if (defined $args->{files} and
      not defined $args->{body} and not defined $args->{body_stream} and
      not defined $ct) {
    $boundary = '';
    $boundary .= $BoundaryAlphabet[rand @BoundaryAlphabet] for 1..50;
    push @$header_list, ['Content-Type', $ct = 'multipart/form-data; boundary=' . $boundary, 'content-type'];
    $has_header->{'content-type'} = 1;
  }
  return {failed => 1, message => "Both |files| and |body| are specified"}
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
        return {failed => 1, message => "File's |body_ref|'s value is utf8-flagged"}
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
     (defined $ct and $ct eq 'application/x-www-form-urlencoded')) and
    not defined $args->{body_stream}
  ) ? 'body' : 'query';
  if (not defined $boundary and defined $args->{params}) {
    if ($param_container eq 'query') {
      $url_record = $url_record->clone;
      $url_record->set_query_params ($args->{params}, append => 1);
    } else { # $param_container eq 'body'
      unless ($has_header->{'content-type'}) {
        push @$header_list, ['Content-Type', $ct = 'application/x-www-form-urlencoded', 'content-type'];
        $has_header->{'content-type'} = 1;
      }
      $args->{body} = serialize_form_urlencoded $args->{params};
    }
  }

  unless ($args->{forwarding}) {
    push @$header_list, ['Accept', '*/*', 'accept']
        unless $has_header->{'accept'};
    push @$header_list, ['Accept-Language', 'en', 'accept-language']
        unless $has_header->{'accept-language'};
    push @$header_list, ['User-Agent', 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.87 Safari/537.36', 'user-agent']
        unless $has_header->{'user-agent'};
  }

  if (defined $args->{bearer}) {
    push @$header_list, ['Authorization' => $auth = 'Bearer ' . encode_web_utf8 $args->{bearer}, 'authorization'];
    $has_header->{authorization} = 1;
  }

  if ($args->{basic_auth}) {
    require Web::Transport::Base64;
    my $bauth = Web::Transport::Base64::encode_web_base64
        (encode_web_utf8 ((defined $args->{basic_auth}->[0] ? $args->{basic_auth}->[0] : '') . ':' .
                          (defined $args->{basic_auth}->[1] ? $args->{basic_auth}->[1] : '')));
    push @$header_list, ['Authorization', $auth = 'Basic ' . $bauth, 'authorization'];
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
         clock => $args->{protocol_clock},
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
      push @$header_list, ['Authorization', $auth = $result->{http_authorization}, 'authorization'];
      $has_header->{authorization} = 1;
    }
    if (defined $result->{body_appended} and
        length $result->{body_appended}) {
      if (not defined $ct) {
        push @$header_list, ['Content-Type', $ct = 'application/x-www-form-urlencoded', 'content-type'];
        $has_header->{'content-type'} = 1;
      }
      $args->{body} .= $result->{body_appended};
    }
    $nostore = 1;
  }

  if (defined $args->{aws4}) {
    require Web::Transport::AWS;
    Web::Transport::AWS->aws4 (
      clock => $args->{protocol_clock},
      method => $method,
      url => $url_record,
      header_list => $header_list, # to be modified!
      signed_headers => $args->{aws4_signed_headers},
      body_ref => (defined $args->{body} ? \($args->{body}) : \''),
      access_key_id => $args->{aws4}->[0],
      secret_access_key => $args->{aws4}->[1],
      region => $args->{aws4}->[2],
      service => $args->{aws4}->[3],
    );
  }

  my $body_reader;
  if (defined $args->{body_stream}) {
    return {failed => 1, message => "Request body not allowed"}
        if $args->{no_body};

    return {failed => 1, message => "No |length|"}
        unless defined $args->{length};
    push @$header_list,
        ['Content-Length', 0+$args->{length}, 'content-length'];

    $body_reader = $args->{body_stream}->get_reader ('byob'); # or throw
  } elsif (defined $args->{body}) {
    return {failed => 1, message => "Request body not allowed"}
        if $args->{no_body};

    push @$header_list, ['Content-Length', length ($args->{body}), 'content-length'];
  }

  if ($args->{superreload}) {
    push @$header_list,
        ['Pragma', 'no-cache', 'pragma'],
        ['Cache-Control', 'no-cache', 'cache-control'];
  }
  $nostore = 1 if
      defined $has_header->{cookie} or
      defined $has_header->{authorization} or
      defined $has_header->{'x-wsse'};
  if ($nostore) {
    push @$header_list, ['Pragma', 'no-cache', 'pragma']
        unless $args->{superreload};
    push @$header_list, ['Cache-Control', 'no-store', 'cache-control'];
  }

  # XXX Accept-Encoding

  for (@$header_list) {
    $_->[1] =~ tr/\x0D\x0A/\x20\x20/;
  }

  return ($method, $url_record, $header_list,
          defined $args->{body} ? \($args->{body}) : undef, $body_reader);
} # create

##   status - The status code of the response.  It must be an integer
##   in the range [0, 999].
##
##   status_text - The reason phrase of the response.  It must be a
##   byte string with no 0x0D or 0x0A byte.  It can be the empty
##   string.  If not defined, default text as defined by the relevant
##   specification, if any, or the empty string is used.
##
##   headers - The headers of the response.  It must be an array
##   reference or a hash reference (see Web::Transport).  If not
##   defined, no header is specified.
##
##   protocol_clock - The clock of the real-world time, used to
##   generate protocol elements specifying the current time, such as
##   HTTP |Date:| header.  If not defined, a |realtime_clock| from
##   Web::DateTime::Clock is used.
##
##   forwarding - Whether this response is received from the upstream
##   and is to be forwarded to the downstream or not.  If this option
##   is true, this method does not generate some headers.  (This
##   option is not used by this method, but is used by
##   Web::Transport::ProxyServerConnection, which invokes this
##   method.)
##
## Returns a response hash reference, or throws an exception.
sub create_response ($$) {
  my $response = {%{$_[1]}};

  unless (defined $response->{status_text}) {
    $response->{status_text} = $Web::Transport::_Defs::ReasonPhrases->{$response->{status} || 0};
    $response->{status_text} = '' unless defined $response->{status_text};
  }
  die Web::Transport::TypeError->new ("Bad |status_text| (utf8-flagged)")
      if utf8::is_utf8 $response->{status_text};

  my $has_header;
  ($response->{headers}, $has_header) = $_[0]->create_header_list
      ($response->{headers});

  unless ($has_header->{date}) {
    my $dt = Web::DateTime->new_from_unix_time
        ($response->{protocol_clock} || Web::DateTime::Clock->realtime_clock->());
    unshift @{$response->{headers}}, ['Date', $dt->to_http_date_string, 'date'];
  }

  return $response;
} # create_response

## Interpret a |headers| value.  See Web::Transport for acceptable
## values.  It either returns an internal headers value (an array
## reference of array references of original header name, header
## value, canonical header name tuples, or throws an exception.
##
## This method is applicable for request headers, as well as response
## headers and trailer headers.
##
## This method does not validate header names and values.
sub create_header_list ($$) {
  my $headers = $_[1];
  my $header_list = [];
  my $has_header = {};
  if (not defined $headers) {
    #
  } elsif (ref $headers eq 'ARRAY') {
    for (@$headers) {
      die Web::Transport::TypeError->new ("Bad headers")
          unless defined $_ and ref $_ eq 'ARRAY';
      ## Header names and values must be byte strings.
      push @$header_list, [$_->[0], $_->[1]];
      my $name_lc = $header_list->[-1]->[0];
      $name_lc =~ tr/A-Z/a-z/; ## ASCII case-insensitive
      $header_list->[-1]->[2] = $name_lc;
      $has_header->{$name_lc} = 1;
    }
  } elsif (ref $headers eq 'HASH') {
    for my $name (keys %$headers) {
      my $name_lc = $name;
      $name_lc =~ tr/A-Z/a-z/; ## ASCII case-insensitive
      if (defined $headers->{$name}) {
        ## Header names and values must be character strings.  (They
        ## usually does not contain any non-ASCII bytes.)
        if (ref $headers->{$name} eq 'ARRAY') {
          push @$header_list, map {
            [(encode_web_utf8 $name), (encode_web_utf8 $_), $name_lc]
          } @{$headers->{$name}};
          $has_header->{$name_lc} = 1 if @{$headers->{$name}};
        } else {
          push @$header_list,
              [(encode_web_utf8 $name), (encode_web_utf8 $headers->{$name}),
               $name_lc];
          $has_header->{$name_lc} = 1;
        }
      }
    }
  } else {
    die Web::Transport::TypeError->new ("Bad headers");
  }
  return ($header_list, $has_header);
} # create_header_list

## See Web::Transport::ProxyServerConnection's documentation (HANDLER
## API OBJECT's |filter_headers| method).
sub filter_headers ($$%) {
  my (undef, $input, %args) = @_;

  my %remove;
  if ($args{proxy_removed}) {
    for (@$input) {
      if ($_->[2] eq 'connection') {
        for (split /,/, $_->[1]) {
          my $v = $_;
          $v =~ tr/A-Z/a-z/; ## ASCII case-insensitive.
          $v =~ s/\A[\x09\x0A\x0D\x20]+//;
          $v =~ s/[\x09\x0A\x0D\x20]+\z//;
          $remove{$v} = 1;
        }
      }
    }
  } # proxy_removed

  my $names = $args{names} || {};

  return [map {
    if ($remove{$_->[2]} or $names->{$_->[2]}) {
      ();
    } elsif ($args{proxy_removed} and
             $Web::Transport::_Defs::Headers->{proxy_removed}->{$_->[2]}) {
      ();
    } elsif ($args{conditional} and
             $Web::Transport::_Defs::Headers->{conditional}->{$_->[2]}) {
      ();
    } else {
      $_;
    }
  } @$input];
} # filter_headers

1;

=head1 HISTORY

The module partially derived from L<Web::UserAgent::Functions> from
<https://github.com/wakaba/perl-web-useragent-functions>.

=head1 LICENSE

Copyright 2009-2013 Hatena <https://www.hatena.ne.jp/>.

Copyright 2014-2018 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
