package HTTPConnectionClient;
use strict;
use warnings;
require utf8;
use Carp;
use HTTPClientBareConnection;
use Web::URL::Canonicalize qw(url_to_canon_url parse_url serialize_parsed_url);
use Web::Transport::RequestConstructor;

use constant DEBUG => $ENV{WEBUA_DEBUG} || 0;

sub new_from_url ($$) {
  my $url = $_[1];
  my $parsed_url = parse_url url_to_canon_url $url, 'about:blank';
  my $origin = defined $parsed_url->{host} ? serialize_parsed_url {
    invalid => $parsed_url->{invalid},
    scheme => $parsed_url->{scheme},
    host => $parsed_url->{host},
    port => $parsed_url->{port},
  } : undef;
  return bless {
    origin => $origin,
    queue => Promise->resolve,
    parent_id => (int rand 100000),
  }, $_[0];
} # new_from_url

sub proxy_manager ($;$) {
  if (@_ > 1) {
    $_[0]->{proxy_manager} = $_[1];
  }
  return $_[0]->{proxy_manager} ||= do {
    require Web::Transport::ProxyManager;
    Web::Transport::ProxyManager->new_from_envs;
  };
} # proxy_manager

sub tls_options ($;$) {
  if (@_ > 1) {
    $_[0]->{tls_options} = $_[1];
  }
  return $_[0]->{tls_options};
} # tls_options

sub max_size ($;$) {
  if (@_ > 1) {
    $_[0]->{max_size} = $_[1];
  }
  return defined $_[0]->{max_size} ? $_[0]->{max_size} : -1;
} # max_size

our $LastResortTimeout;
$LastResortTimeout = 60*10 unless defined $LastResortTimeout;
sub last_resort_timeout ($;$) {
  if (@_ > 1) {
    $_[0]->{last_resort_timeout} = $_[1];
  }
  return defined $_[0]->{last_resort_timeout} ? $_[0]->{last_resort_timeout} : $LastResortTimeout;
} # last_resort_timeout

sub _connect ($$) {
  my ($self, $url_record) = @_;

  if (defined $self->{client} and $self->{client}->is_active) {
    return Promise->resolve ($self->{client});
  }

  return Promise->resolve->then (sub {
    if (defined $self->{client}) {
      warn "$self->{parent_id}: @{[__PACKAGE__]}: Current connection is no longer active @{[scalar gmtime]}\n" if DEBUG;
      return $self->{client}->abort;
    } else {
      warn "$self->{parent_id}: @{[__PACKAGE__]}: New connection @{[scalar gmtime]}\n" if DEBUG;
    }
  })->then (sub {
    $self->{client} = HTTPClientBareConnection->new_from_url_record ($url_record);
    $self->{client}->parent_id ($self->{parent_id});
    $self->{client}->proxy_manager ($self->proxy_manager);
    $self->{client}->tls_options ($self->tls_options);
    $self->{client}->last_resort_timeout ($self->last_resort_timeout);
    return $self->{client};
  });
} # _connect

sub request ($$%) {
  my ($self, $url, %args) = @_;

  my ($method, $url_record, $header_list, $body_ref)
      = Web::Transport::RequestConstructor->create ($url, \%args);
  if (defined $body_ref and utf8::is_utf8 ($$body_ref)) {
    croak "|body| is utf8-flagged";
  }

  my $url_origin = defined $url_record->{host} ? serialize_parsed_url {
    invalid => $url_record->{invalid},
    scheme => $url_record->{scheme},
    host => $url_record->{host},
    port => $url_record->{port},
  } : undef;

  if (not defined $self->{origin} or
      not defined $url_origin or
      not $self->{origin} eq $url_origin) {
    return Promise->reject
        ("Bad origin |$url_origin| (|$self->{origin}| expected)");
  }

  my $return_ok;
  my $return_promise = Promise->new (sub { $return_ok = $_[0] });
  $self->{queue} ||= Promise->resolve;
  $self->{queue} = $self->{queue}->then (sub {
    my $body = [];
    my $body_length = 0;
    my $max = $self->max_size;
    my $then = sub {
      return $_[0]->request ($method, $url_record, $header_list, $body_ref, sub {
        if (defined $_[2]) {
          push @$body, \($_[2]);
          if ($max >= 0) {
            $body_length += length $_[2];
            if ($body_length >= $max) {
              $_[0]->abort (message => "Response body is larger than max_size ($max)");
            }
          }
        }
      });
    };
    my $return = $self->_connect ($url_record)->then ($then)->then (sub {
      my $result = $_[0];
      if ($result->{failed} and $result->{can_retry}) {
        $body = [];
        $body_length = 0;
        return $self->_connect ($url_record)->then ($then)->then (sub {
          $_[0]->{body} = $body unless $_[0]->{failed};
          return bless $_[0], 'HTTPConnectionClient::Response';
        });
      } else {
        $result->{body} = $body unless $result->{failed};
        return bless $result, 'HTTPConnectionClient::Response';
      }
    });
    $return_ok->($return);
    return $return->catch (sub { });
  });
  return $return_promise;
} # request

sub close ($) {
  my $self = $_[0];
  my $queue = delete $self->{queue};
  return Promise->resolve unless defined $queue;
  return $queue->then (sub {
    my $client = delete $self->{client};
    return $client->close if defined $client;
  })->then (sub {
    warn "$self->{parent_id}: @{[__PACKAGE__]}: Closed @{[scalar gmtime]}\n" if DEBUG;
  });
} # close

sub DESTROY ($) {
  $_[0]->close (message => "Aborted by DESTROY of $_[0]");

  local $@;
  eval { die };
  warn "Reference to @{[ref $_[0]]} is not discarded before global destruction\n"
      if $@ =~ /during global destruction/;

} # DESTROY

package HTTPConnectionClient::Response;

sub is_network_error ($) {
  return $_[0]->{failed};
} # is_network_error

sub network_error_message ($) {
  return $_[0]->{message};
} # network_error_message

sub status ($) {
  return $_[0]->{status} || 0;
} # status

## HTTP::Response compatibility
*code = \&status;

## HTTP::Response compatibility
sub is_success ($) {
  return 0 if $_[0]->{failed};
  return (200 <= $_[0]->{status} and $_[0]->{status} <= 299);
} # is_success

## HTTP::Response compatibility
sub is_error ($) {
  return 1 if $_[0]->{failed};
  return (400 <= $_[0]->{status} and $_[0]->{status} <= 599);
} # is_error

## HTTP::Response compatibility
sub status_line ($) {
  return $_[0]->status . ' ' . (defined $_[0]->{reason} ? $_[0]->{reason} : '');
} # status_line

## HTTP::Response compatibility
sub header ($$) {
  my $name = $_[1];
  $name =~ tr/A-Z/a-z/; ## ASCII case-insensitive
  for (@{$_[0]->{headers}}) {
    if ($_->[2] eq $name) {
      return $_->[1];
    }
  }
  return undef;
} # header

sub body_bytes ($) {
  return undef unless defined $_[0]->{body};
  return join '', map { $$_ } @{$_[0]->{body}};
} # body_bytes

## HTTP::Response compatibility
sub content ($) {
  return '' if not defined $_[0]->{body};
  return $_[0]->body_bytes;
} # content

sub incomplete ($) {
  return $_[0]->{incomplete};
} # incomplete

## HTTP::Response compatibility
sub as_string ($) {
  my $self = $_[0];
  return 'HTTP/1.1 ' . $self->status_line . "\x0D\x0A" .
      (join '', map { "$_->[0]: $_->[1]\x0D\x0A" } @{$_[0]->{headers}}) .
      "\x0D\x0A" .
      $_[0]->content;
} # as_string

1;
