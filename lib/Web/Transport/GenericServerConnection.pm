package Web::Transport::GenericServerConnection;
use strict;
use warnings;
our $VERSION = '1.0';
use ArrayBuffer;
use DataView;
use AnyEvent;
use Promise;
use Promised::Flow;
use Web::Encoding;
use Web::Host;
use Web::Transport::TCPStream;
use Web::Transport::TLSStream;
use Web::Transport::HTTPStream;

## This is a superclass of Web::Transport::PSGIServerConnection and
## Web::Transport::ProxyServerConnection.

push our @CARP_NOT, qw(
  ArrayBuffer
  Web::Transport::HTTPStream
  Web::Transport::HTTPStream::Stream
  Web::Transport::PSGIServerConnection
  Web::Transport::ProxyServerConnection
);

sub new_from_aeargs_and_opts ($$$) {
  my ($class, $aeargs, $opts) = @_;
  my $self = bless {}, $class;
  my $socket;
  if ($aeargs->[1] eq 'unix/') {
    require Web::Transport::UnixStream;
    $socket = {
      class => 'Web::Transport::UnixStream',
      server => 1, fh => $aeargs->[0],
      parent_id => $opts->{parent_id},
    };
  } else {
    $socket = {
      class => 'Web::Transport::TCPStream',
      server => 1, fh => $aeargs->[0],
      host => Web::Host->parse_string ($aeargs->[1]), port => $aeargs->[2],
      parent_id => $opts->{parent_id},
    };
  }
  if ($opts->{tls}) {
    $socket = {
      %{$opts->{tls}},
      class => 'Web::Transport::TLSStream',
      server => 1,
      parent => $socket,
    };
  }

  $self->{server_header} = encode_web_utf8
      (defined $opts->{server_header} ? $opts->{server_header} : 'Server');
  $self->{debug} = defined $opts->{debug} ? $opts->{debug} : ($ENV{WEBSERVER_DEBUG} || 0);

  $self->{connection} = Web::Transport::HTTPStream->new ({
    parent => $socket,
    server => 1,
    debug => $self->{debug},
  });
  $self->{completed_cv} = AE::cv;
  $self->{completed_cv}->begin;
  my $reader = $self->{connection}->streams->get_reader;
  my $read; $read = sub {
    return $reader->read->then (sub {
      return if $_[0]->{done};
      $self->{completed_cv}->begin;
      promised_cleanup {
        $self->{completed_cv}->end;
      } $self->_handle_stream ($_[0]->{value}, $opts);
      return $read->();
    });
  }; # $read
  promised_cleanup { undef $read } $read->();
  $self->{connection}->closed->then (sub { $self->{completed_cv}->end });
  $self->{completed} = Promise->from_cv ($self->{completed_cv});
  return $self;
} # new_from_aeargs_and_opts

sub id ($) {
  return $_[0]->{connection}->info->{id};
} # id

sub onexception ($;$) {
  if (@_ > 1) {
    $_[0]->{onexception} = $_[1];
  }
  return $_[0]->{onexception} || sub { warn $_[1] };
} # onexception

sub closed ($) {
  return $_[0]->{connection}->closed;
} # closed

sub completed ($) {
  return $_[0]->{completed};
} # completed

sub close_after_current_response ($;%) {
  my ($self, %args) = @_;
  my $timeout = $args{timeout};
  $timeout = 10 unless defined $timeout;
  $self->{connection}->close_after_current_stream;
  my $timer;
  if ($timeout > 0) {
    $timer = AE::timer $timeout, 0, sub {
      $self->{connection}->abort
          ("|close_after_current_response| timeout ($timeout)");
      undef $timer;
    };
  }
  return $self->completed->then (sub {
    undef $timer;
  });
} # close_after_current_response

sub DESTROY ($) {
  local $@;
  eval { die };
  warn "$$: Reference to @{[ref $_[0]]} is not discarded before global destruction\n"
      if $@ =~ /during global destruction/;
} # DESTROY

1;

=head1 LICENSE

Copyright 2016-2017 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

