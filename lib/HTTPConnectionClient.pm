package HTTPConnectionClient;
use strict;
use warnings;
use HTTPClientBareConnection;
use Resolver;
use Web::Encoding qw(encode_web_utf8);
use Web::URL::Canonicalize qw(url_to_canon_url parse_url serialize_parsed_url
                              get_default_port);

sub new_from_url ($$) {
  my $url = $_[1];
  my $parsed_url = parse_url url_to_canon_url $url, 'about:blank';
  my $origin = serialize_parsed_url {
    invalid => $parsed_url->{invalid},
    scheme => $parsed_url->{scheme},
    host => $parsed_url->{host},
    port => $parsed_url->{port},
  };
  return bless {
    origin => $origin,
    queue => Promise->resolve,
  }, $_[0];
} # new_from_url

sub _connect ($$) {
  my ($self, $url_record) = @_;

  if (defined $self->{client} and $self->{client}->is_active) {
    return Promise->resolve ($self->{client});
  }

  my ($addr, $port);
  return Resolver->resolve_name ($url_record->{host})->then (sub {
    $addr = $_[0];
    return {failed => 1, message => "Can't resolve |$url_record->{host}|"}
        unless defined $addr;

    $port = $url_record->{port};
    $port = get_default_port $url_record->{scheme} if not defined $port;
    return {failed => 1, message => "No port specified"}
        unless defined $port;

    return $self->{client}->abort if defined $self->{client};
  })->then (sub {
    return $self->{client} = HTTPClientBareConnection->new_from_addr_and_port
        (encode_web_utf8 ($addr), 0+$port);
  });
} # _connect

sub request ($$%) {
  my ($self, $url, %args) = @_;

  my $method = encode_web_utf8 (defined $args{method} ? $args{method} : 'GET');

  my $headers = $args{headers} || {};
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

  push @$header_list, ['Accept', '*/*'] unless $has_header->{'accept'};
  push @$header_list, ['Accept-Language', 'en'] unless $has_header->{'accept-language'};
  push @$header_list, ['User-Agent', 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.87 Safari/537.36'] unless $has_header->{'user-agent'};
  # XXX Content-Length

  # XXX Cookie
  # XXX Authorization

  if ($args{superreload} or
      defined $has_header->{cookie} or
      defined $has_header->{authorization}) {
    push @$header_list, ['Pragma', 'no-cache'], ['Cache-Control', 'no-cache'];
  }

  # Accept-Encoding DNT Upgrade-Insecure-Requests

  my $url_record = parse_url url_to_canon_url $url, 'about:blank';
  my $url_origin = serialize_parsed_url {
    invalid => $url_record->{invalid},
    scheme => $url_record->{scheme},
    host => $url_record->{host},
    port => $url_record->{port},
  };

  if (not defined $self->{origin} or
      not defined $url_origin or
      not $self->{origin} eq $url_origin) {
    return Promise->reject
        ("Bad origin |$url_origin| (|$self->{origin}| expected)");
  }

  my $return_ok;
  my $return_promise = Promise->new (sub { $return_ok = $_[0] });
  $self->{queue} = $self->{queue}->then (sub {
    my $then = sub {
      return $_[0]->request ($method, $url_record, $header_list, sub {
#        warn Dumper [$_[1], $_[2]];
      });
    };
    my $return = $self->_connect ($url_record)->then ($then)->then (sub {
      my $result = $_[0];
      if ($result->{failed} and $result->{can_retry}) {
        return $self->_connect ($url_record)->then ($then);
      } else {
        return $result;
      }
    });
    $return_ok->($return);
    return $return->catch (sub { });
  });
  return $return_promise;
} # request

sub close ($) {
  my $self = $_[0];
  return Promise->resolve unless defined $self->{client};
  return $self->{queue}->then (sub {
    return $self->{client}->close->then (sub {
      delete $self->{client};
      $self->{queue} = Promise->resolve;
      return undef;
    });
  });
} # close

sub DESTROY ($) {
  $_[0]->close (message => "Aborted by DESTROY of $_[0]");

  local $@;
  eval { die };
  warn "Reference to @{[ref $_[0]]} is not discarded before global destruction\n"
      if $@ =~ /during global destruction/;

} # DESTROY

1;
