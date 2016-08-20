package Web::Transport::WSClient;
use strict;
use warnings;
our $VERSION = '1.0';
use Carp;
use Web::URL;
use Web::Encoding;
use Web::Transport::ClientBareConnection;
use Web::Transport::RequestConstructor;

use constant DEBUG => $ENV{WEBUA_DEBUG} || 0;

sub new ($%) {
  my ($class, %args) = @_;
  return Promise->resolve->then (sub {

    my ($method, $url_record, $header_list, $body_ref)
        = Web::Transport::RequestConstructor->create
            ({%args, get_only => 1, no_body => 1});
    if (ref $method) { # error
      die bless $method, __PACKAGE__ . '::Response';
    }

    die bless {
      failed => 1,
      message => "Bad URL scheme |@{[$url_record->scheme]}|",
    }, __PACKAGE__ . '::Response'
        unless $url_record->scheme eq 'wss' or $url_record->scheme eq 'ws';
    $url_record = Web::URL->parse_string
        (($url_record->scheme eq 'wss' ? 'https' : 'http') . '://' . $url_record->hostport . $url_record->pathquery);

    my $self = bless {parent_id => (int rand 100000)}, $class;

    $args{proxy_manager} ||= do {
      require Web::Transport::ENVProxyManager;
      Web::Transport::ENVProxyManager->new_from_envs;
    };

    $args{resolver} ||= do {
      require Web::Transport::PlatformResolver;
      require Web::Transport::CachedResolver;
      require Web::DateTime::Clock;
      Web::Transport::CachedResolver->new_from_resolver_and_clock
          (Web::Transport::PlatformResolver->new,
           Web::DateTime::Clock->monotonic_clock);
    };

    $self->{client} = Web::Transport::ClientBareConnection->new_from_url
        ($url_record);
    $self->{client}->parent_id ($self->{parent_id});
    $self->{client}->proxy_manager ($args{proxy_manager});
    $self->{client}->resolver ($args{resolver});
    $self->{client}->tls_options ($args{tls_options});

    warn "$self->{parent_id}: @{[__PACKAGE__]}: New connection @{[scalar gmtime]}\n" if DEBUG;

    my $cb = $args{cb};
    push @$header_list, [Upgrade => 'websocket'], [Connection => 'Upgrade'];
    my $in_ws = 0;
    return $self->{client}->request ('GET', $url_record, $header_list, undef, $args{superreload}, 'ws', sub {
      if ($_[1]->{ws_connection_established}) {
        if (defined $_[3]) {
          return $cb->($self, $_[2], $_[3]);
        } else {
          $in_ws = 1;
          return $cb->($self, undef, undef);
        }
      }
    })->then (sub {
      my ($response, $result) = @{$_[0]};
      return $self->close->then (sub {
        if (not defined $response or $response->{ws_connection_established}) {
          return bless $result, __PACKAGE__ . '::Response';
        } else {
          $response->{ws} = 2;
          return bless $response, __PACKAGE__ . '::Response';
        }
      });
    }, sub { # unexpected exception
      my $error = $_[0];
      return $self->close->then (sub {
        die $error;
      });
    });
  });
} # new

sub send_binary ($$) {
  my $self = $_[0];
  croak "Bad state"
      if not defined $self->{client} or defined $self->{closed_promise};
  croak "Data is utf8-flagged"
      if utf8::is_utf8 ($_[1]);
  my $http = $self->{client}->{http};
  $http->send_binary_header (length $_[1]);
  $http->send_data (\($_[1]));
} # send_binary

sub send_text ($$) {
  my $self = $_[0];
  croak "Bad state"
      if not defined $self->{client} or defined $self->{closed_promise};
  my $http = $self->{client}->{http};
  my $text = encode_web_utf8 $_[1];
  $http->send_binary_header (length $text);
  $http->send_data (\$text);
} # send_text

sub close ($) {
  my $self = $_[0];
  return $self->{closed_promise} ||= do {
    my $client = delete $self->{client};
    if (defined $client) {
      $client->close->then (sub {
        warn "$self->{parent_id}: @{[__PACKAGE__]}: Closed @{[scalar gmtime]}\n" if DEBUG;
      });
    } else {
      Promise->resolve;
    }
  };
} # close

sub DESTROY ($) {
  $_[0]->close;

  local $@;
  eval { die };
  warn "Reference to @{[ref $_[0]]} is not discarded before global destruction\n"
      if $@ =~ /during global destruction/;

} # DESTROY

package Web::Transport::WSClient::Response;
use overload '""' => 'stringify', fallback => 1;

sub is_network_error ($) {
  return $_[0]->{failed} && !$_[0]->{ws};
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
  return 0 if $_[0]->{failed} || ($_[0]->{ws} && $_[0]->{ws} == 1);
  return (200 <= $_[0]->{status} and $_[0]->{status} <= 299);
} # is_success

## HTTP::Response compatibility
sub is_error ($) {
  return 1 if $_[0]->{failed};
  return (400 <= $_[0]->{status} and $_[0]->{status} <= 599);
} # is_error

sub status_text ($) {
  return defined $_[0]->{reason} ? $_[0]->{reason} : '';
} # status_text

## HTTP::Response compatibility
sub status_line ($) {
  return $_[0]->status . ' ' . $_[0]->status_text;
} # status_line

sub ws_code ($) {
  if ($_[0]->{ws} and $_[0]->{ws} == 1) {
    return $_[0]->{status};
  } else {
    return 1006;
  }
} # ws_code

sub ws_reason ($) {
  if ($_[0]->{ws} and $_[0]->{ws} == 1) {
    return $_[0]->{reason};
  } else {
    return '';
  }
} # ws_reason

sub ws_closed_cleanly ($) {
  return $_[0]->{cleanly};
} # ws_closed_cleanly

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

sub stringify ($) {
  my $self = $_[0];
  if ($self->{ws}) {
    if ($self->{ws} == 2) {
      return "WS handshake error: @{[$self->status_line]}";
    } else {
      return sprintf "WS closed (%d |%s| failed = %d, cleanly = %d)",
          $self->{status}, $self->{reason},
          $self->{failed} ? 1 : 0, $self->{cleanly} ? 1 : 0;
    }
  } elsif ($self->is_network_error) {
    return "Network error: @{[$self->network_error_message]}";
  } else {
    return "Response: @{[$self->status_line]}";
  }
} # stringify

1;

=head1 LICENSE

Copyright 2016 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
