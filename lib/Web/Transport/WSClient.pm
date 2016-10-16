package Web::Transport::WSClient;
use strict;
use warnings;
our $VERSION = '1.0';
use Carp;
use Web::URL;
use Web::Encoding;
use Web::Transport::ClientBareConnection;
use Web::Transport::RequestConstructor;
use Web::Transport::Response;

use constant DEBUG => $ENV{WEBUA_DEBUG} || 0;

sub new ($%) {
  my ($class, %args) = @_;
  return Promise->resolve->then (sub {

    my ($method, $url_record, $header_list, $body_ref)
        = Web::Transport::RequestConstructor->create
            ({%args, get_only => 1, no_body => 1});
    if (ref $method) { # error
      die bless $method, 'Web::Transport::Response';
    }

    die bless {
      failed => 1,
      message => "Bad URL scheme |@{[$url_record->scheme]}|",
    }, 'Web::Transport::Response'
        unless $url_record->scheme eq 'wss' or $url_record->scheme eq 'ws';
    $url_record = Web::URL->parse_string
        (($url_record->scheme eq 'wss' ? 'https' : 'http') . '://' . $url_record->hostport . $url_record->pathquery);

    my $self = bless {parent_id => ($$ . '.' . ++$Web::Transport::NextID)}, $class;

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
    my $bad_response;
    return $self->{client}->request ('GET', $url_record, $header_list, undef, $args{superreload}, 'ws', sub {
      if ($_[1]->{ws_connection_established}) {
        if (defined $_[3]) {
          if ($_[3] eq 'closing') {
            $self->{ws_closing} = 1;
          } else { # text or binary
            return $cb->($self, $_[2], $_[3]);
          }
        } else {
          $in_ws = 1;
          return $cb->($self, undef, undef);
        }
      } else {
        $bad_response ||= {%{$_[1]}};
        return $self->{client}->abort (message => "WebSocket handshake failed");
      }
    })->then (sub {
      my ($response, $result) = @{$_[0]};
      return $self->close->then (sub {
        if (defined $bad_response) {
          $bad_response->{ws} = 2;
          return bless $bad_response, 'Web::Transport::Response';
        } elsif (not defined $response or $response->{ws_connection_established}) {
          return bless $result, 'Web::Transport::Response';
        } else {
          $response->{ws} = 2;
          return bless $response, 'Web::Transport::Response';
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

# XXX test and documentation
sub can_send ($) {
  my $self = $_[0];
  return (defined $self->{client} && !defined $self->{closed_promise} && !$self->{ws_closing});
} # can_send

sub send_binary ($$) {
  my $self = $_[0];
  croak "Bad state"
      if not defined $self->{client} or defined $self->{closed_promise} or
         $self->{ws_closing};
  croak "Data is utf8-flagged"
      if utf8::is_utf8 ($_[1]);
  my $http = $self->{client}->{http};
  $http->send_binary_header (length $_[1]);
  $http->send_data (\($_[1]));
} # send_binary

# XXX test
sub send_text ($$) {
  my $self = $_[0];
  croak "Bad state"
      if not defined $self->{client} or defined $self->{closed_promise} or
         $self->{ws_closing};
  my $http = $self->{client}->{http};
  my $text = encode_web_utf8 $_[1];
  $http->send_text_header (length $text);
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

1;

=head1 LICENSE

Copyright 2016 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
