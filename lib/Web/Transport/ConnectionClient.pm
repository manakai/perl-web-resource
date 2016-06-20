package Web::Transport::ConnectionClient;
use strict;
use warnings;
our $VERSION = '1.0';
require utf8;
use Carp;
use Web::DomainName::Canonicalize qw(canonicalize_url_host);
use Web::Transport::ClientBareConnection;
use Web::Transport::RequestConstructor;

use constant DEBUG => $ENV{WEBUA_DEBUG} || 0;

sub new_from_url ($$) {
  my $origin = $_[1]->get_origin;
  croak "The URL does not have a tuple origin" if $origin->is_opaque;
  return bless {
    base_url => $_[1],
    origin => $origin,
    queue => Promise->resolve,
    parent_id => (int rand 100000),
  }, $_[0];
} # new_from_url

sub new_from_host ($$) {
  my $host = canonicalize_url_host $_[1];
  croak "Not a valid host: |$_[1]|" unless defined $host;
  my $url = Web::URL->parse_string ('https://' . $host);
  return $_[0]->new_from_url ($url);
} # new_from_host

sub origin ($) {
  return $_[0]->{origin};
} # origin

sub proxy_manager ($;$) {
  if (@_ > 1) {
    $_[0]->{proxy_manager} = $_[1];
  }
  return $_[0]->{proxy_manager} ||= do {
    require Web::Transport::ENVProxyManager;
    Web::Transport::ENVProxyManager->new_from_envs;
  };
} # proxy_manager

sub resolver ($;$) {
  if (@_ > 1) {
    $_[0]->{resolver} = $_[1];
    return unless defined wantarray;
  }
  return $_[0]->{resolver} ||= do {
    require Web::Transport::PlatformResolver;
    require Web::Transport::CachedResolver;
    require Web::DateTime::Clock;
    Web::Transport::CachedResolver->new_from_resolver_and_clock
        (Web::Transport::PlatformResolver->new,
         Web::DateTime::Clock->monotonic_clock);
  };
} # resolver

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
    $self->{client} = Web::Transport::ClientBareConnection->new_from_url
        ($url_record);
    $self->{client}->parent_id ($self->{parent_id});
    $self->{client}->proxy_manager ($self->proxy_manager);
    $self->{client}->resolver ($self->resolver);
    $self->{client}->tls_options ($self->tls_options);
    $self->{client}->last_resort_timeout ($self->last_resort_timeout);
    return $self->{client};
  });
} # _connect

sub request ($%) {
  my ($self, %args) = @_;
  $args{debug_prefix} = "$self->{parent_id}: @{[__PACKAGE__]}";

  my ($return_ok, $return_ng);
  my $return_promise = Promise->new (sub { ($return_ok, $return_ng) = @_ });
  $self->{queue} ||= Promise->resolve;
  $self->{queue} = $self->{queue}->then (sub {

    $args{base_url} ||= $self->{base_url};
    my ($method, $url_record, $header_list, $body_ref)
        = Web::Transport::RequestConstructor->create (\%args);
    if (ref $method) { # error
      $return_ng->(bless $method, __PACKAGE__ . '::Response');
      return;
    }

    if (defined $body_ref and utf8::is_utf8 ($$body_ref)) {
      $return_ng->(bless {failed => 1,
                          message => "|body| is utf8-flagged"},
                   __PACKAGE__ . '::Response');
      return;
    }

    my $url_origin = $url_record->get_origin;
    unless ($url_origin->same_origin_as ($self->{origin})) {
      $return_ng->(bless {failed => 1,
                          message => "Bad URL origin |@{[$url_origin->to_ascii]}| (|@{[$self->{origin}->to_ascii]}| expected)"},
                   __PACKAGE__ . '::Response');
      return;
    }

    my $body = [];
    my $body_length = 0;
    my $max = $self->max_size;
    my $no_cache = $args{is_superreload}; # XXX per spec, this should look "cache mode"...
    my $then = sub {
      return $_[0]->request ($method, $url_record, $header_list, $body_ref, $no_cache, sub {
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
          return bless $_[0], __PACKAGE__ . '::Response';
        });
      } else {
        $result->{body} = $body unless $result->{failed};
        return bless $result, __PACKAGE__ . '::Response';
      }
    }); # $return
    $return_ok->($return);
    return $return->catch (sub { });
  })->catch (sub {
    $return_ng->($_[0]);
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

package Web::Transport::ConnectionClient::Response;

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

=head1 LICENSE

Copyright 2016 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
