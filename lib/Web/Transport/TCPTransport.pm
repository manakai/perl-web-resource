package Web::Transport::TCPTransport;
use strict;
use warnings;
our $VERSION = '1.0';
require utf8;
use Carp qw(croak);
use Errno qw(EAGAIN EWOULDBLOCK EINTR);
use Socket qw(IPPROTO_TCP TCP_NODELAY SOL_SOCKET SO_KEEPALIVE SO_OOBINLINE SO_LINGER);
use AnyEvent::Util qw(WSAEWOULDBLOCK);
use AnyEvent::Socket qw(tcp_connect);
use Promise;
use Web::Host;

## Note that this class is also used as the base of the
## |Web::Transport::UNIXDomainSocket| class.

sub new ($%) {
  my $self = bless {}, shift;
  my $args = $self->{args} = {@_};
  croak "Bad |fh|" if $args->{server} and not defined $args->{fh};
  croak "Bad |host|" unless defined $args->{host} and $args->{host}->is_ip;
  $args->{addr} = $args->{host}->text_addr;
  croak "Bad |port|" unless defined $args->{port};
  croak "utf8-flagged |port|" if utf8::is_utf8 $args->{port};
  croak "Bad |id|" if defined $args->{id} and utf8::is_utf8 ($args->{id});
  $self->{id} = (defined $args->{id} ? $args->{id} : (defined $args->{parent_id} ? $args->{parent_id} : $$) . '.' . ++$Web::Transport::NextID);
  return $self;
} # new

sub start ($$) {
  my $self = $_[0];
  croak "Bad state" if not defined $self->{args};
  $self->{cb} = $_[1];
  my $args = delete $self->{args};

  return Promise->new (sub {
    my ($ok, $ng) = @_;
    if (defined $args->{fh}) {
      $ok->($args->{fh});
    } else {
      if ($args->{addr} eq '127.0.53.53') {
        return $ng->('ICANN_NAME_COLLISION');
      }
      tcp_connect $args->{addr}, $args->{port}, sub {
        return $ng->($!) unless $_[0];
        $ok->($_[0]);
      };
    }
  })->then (sub {
    $self->{fh} = $_[0];
    my $info = {is_server => !!$args->{server}};
    if ($self->type eq 'TCP') {
      my ($p, $h) = AnyEvent::Socket::unpack_sockaddr getsockname $self->{fh};
      $info->{local_host} = Web::Host->new_from_packed_addr ($h);
      $info->{local_port} = $p;
      $info->{remote_host} = $args->{host};
      $info->{remote_port} = 0+$args->{port};
    }
    AnyEvent::Util::fh_nonblocking $self->{fh}, 1;

    ## Applied to TCP only (not applied to Unix domain socket)
    setsockopt $self->{fh}, SOL_SOCKET, SO_OOBINLINE, 0;
    setsockopt $self->{fh}, IPPROTO_TCP, TCP_NODELAY, 1;
    setsockopt $self->{fh}, SOL_SOCKET, SO_KEEPALIVE, 1;
    # XXX KA options

    $self->{wq} = [];
    $self->_start_write;

    $self->{rw} = AE::io $self->{fh}, 0, sub {
      my $buffer = '';
      my $l = sysread $self->{fh}, $buffer, 128*1024, 0;
      if (defined $l) {
        if ($l > 0) {
          AE::postpone { $self->{cb}->($self, 'readdata', \$buffer) };
        } else {
          delete $self->{rw};
          $self->{read_closed} = 1;
          AE::postpone { $self->{cb}->($self, 'readeof', {message => "EOF received"}) };
          $self->_close if $self->{write_closed};
        }
      } elsif ($! != EAGAIN && $! != EINTR && $! != EWOULDBLOCK && $! != WSAEWOULDBLOCK) {
        my $wc = $self->{write_closed};
        $self->{read_closed} = 1;
        $self->{write_closed} = 1;
        $self->{write_shutdown} = 1;
        delete $self->{rw};
        my $err = $!;
        AE::postpone {
          $self->{cb}->($self, 'readeof', {failed => 1,
                                           errno => 0+$err,
                                           message => "$err"});
          $self->{cb}->($self, 'writeeof', {failed => 1,
                                            message => 'Closed by read error'})
              unless $wc;
        };
        $self->_close;
      }
    }; # $self->{rw}

    $self->{info} = $info;
    AE::postpone {
      $self->{cb}->($self, 'open');
    };
  });
} # start

sub id ($) { return $_[0]->{id} }
sub type ($) { return 'TCP' }
sub layered_type ($) { return $_[0]->type }
sub info ($) { return $_[0]->{info} } # or undef

sub request_mode ($;$) {
  if (@_ > 1) {
    if ($_[1] eq 'HTTP proxy') {
      $_[0]->{request_mode} = 'HTTP proxy';
    } else {
      delete $_[0]->{request_mode};
    }
  }
  return $_[0]->{request_mode} || 'default';
} # request_mode

sub read_closed ($) { return $_[0]->{read_closed} }
sub write_closed ($) { return $_[0]->{write_closed} }
sub write_to_be_closed ($) { return $_[0]->{write_closed} || $_[0]->{write_shutdown} }

sub _start_write ($) {
  my $self = $_[0];
  croak "Bad state" unless defined $self->{wq};
  return unless @{$self->{wq}};
  return if defined $self->{ww};

  my $run = sub {
    while (@{$self->{wq}}) {
      my $w = shift @{$self->{wq}};
      if (@$w == 3) { # data
        my $l = syswrite $self->{fh}, ${$w->[0]}, $w->[1], $w->[2];
        if (defined $l) {
          $w->[2] += $l;
          my $r = (length ${$w->[0]}) - $w->[2];
          if ($r > 0) {
            unshift @{$self->{wq}}, $w;
            return;
          }
        } elsif ($! != EAGAIN && $! != EINTR && $! != EWOULDBLOCK && $! != WSAEWOULDBLOCK) {
          my $rc = $self->{read_closed};
          $self->{read_closed} = 1;
          $self->{write_closed} = 1;
          $self->{write_shutdown} = 1;
          my $err = $!;
          AE::postpone {
            $self->{cb}->($self, 'writeeof', {failed => 1,
                                              errno => 0+$err,
                                              message => "$err"});
            $self->{cb}->($self, 'readeof', {failed => 1,
                                             message => 'Closed by write error'})
                unless $rc;
          };
          $self->_close;
          return;
        }
      } elsif (@$w == 2) { # promise
        $w->[0]->();
        return unless defined $self->{wq};
      } else {
        die "Bad wq data (l = @{[0+@$w]})";
      }
    } # while
    delete $self->{ww} unless @{$self->{wq}};
  }; # $run
  #$run->();

  $self->{ww} = AE::io $self->{fh}, 1, sub {
    $run->();
  } if defined $self->{wq} and @{$self->{wq}};
} # _start_write

sub push_write ($$;$$) {
  my ($self, $ref, $offset, $length) = @_;
  croak "Bad state (write shutdown)" if $self->{write_shutdown};
  croak "Bad state (no wq)" if not defined $self->{wq};
  croak "Data is utf8-flagged" if utf8::is_utf8 $$ref;
  $offset ||= 0;
  croak "Bad offset" if $offset > length $$ref;
  $length = (length $$ref) - $offset unless defined $length;
  croak "Bad length" if $offset + $length > length $$ref;
  return if $length <= 0;
  push @{$self->{wq}}, [$ref, $length, $offset];
  $self->_start_write;
} # push_write

sub push_promise ($) {
  my $self = $_[0];
  croak "Bad state (write shutdown)" if $self->{write_shutdown};
  croak "Bad state (no wq)" if not defined $self->{wq};
  my ($ok, $ng);
  my $p = Promise->new (sub { ($ok, $ng) = @_ });
  push @{$self->{wq}}, [$ok, $ng];
  $self->_start_write;
  return $p;
} # push_promise

sub push_shutdown ($) {
  my $self = $_[0];
  croak "Bad state (write shutdown)" if $self->{write_shutdown};
  croak "Bad state (no wq)" if not defined $self->{wq};
  my ($ok, $ng);
  my $p = Promise->new (sub { ($ok, $ng) = @_ });
  push @{$self->{wq}}, [sub {
    shutdown $self->{fh}, 1;
    $self->{write_closed} = 1;
    AE::postpone { $self->{cb}->($self, 'writeeof', {message => "Write shutdown"}) };
    $self->_close if $self->{read_closed};
    $ok->();
  }, $ng];
  $self->{write_shutdown} = 1;
  $self->_start_write;
  return $p;
} # push_shutdown

## For tests only
sub _push_reset ($) {
  my $self = $_[0];
  croak "Bad state" if not defined $self->{wq} or $self->{write_shutdown};
  my ($ok, $ng);
  my $p = Promise->new (sub { ($ok, $ng) = @_ });
  push @{$self->{wq}}, [sub {
    setsockopt $self->{fh}, SOL_SOCKET, SO_LINGER, pack "II", 1, 0;
    my $wc = $self->{write_closed};
    my $rc = $self->{read_closed};
    $self->{write_closed} = 1;
    $self->{read_closed} = 1;
    my $reason = 'Reset sent';
    AE::postpone {
      $self->{cb}->($self, 'writeeof', {failed => 1, message => $reason})
          unless $wc;
      $self->{cb}->($self, 'readeof', {failed => 1, message => $reason})
          unless $rc;
    };
    $self->_close;
    $ok->();
  }, $ng];
  $self->{write_shutdown} = 1;
  $self->_start_write;
  return $p;
} # _push_reset

sub abort ($;%) {
  my ($self, %args) = @_;
  delete $self->{args};
  shutdown $self->{fh}, 2 if defined $self->{fh};
  my $wc = $self->{write_closed};
  my $rc = $self->{read_closed};
  $self->{write_closed} = 1;
  $self->{read_closed} = 1;
  $self->{write_shutdown} = 1;
  my $reason = defined $args{message} ? $args{message} : 'Aborted';
  AE::postpone {
    $self->{cb}->($self, 'writeeof', {failed => 1, message => $reason})
        unless $wc;
    $self->{cb}->($self, 'readeof', {failed => 1, message => $reason})
        unless $rc;
  } if defined $self->{fh} and not ($wc and $rc);
  $self->_close;
} # abort

sub _close ($$) {
  my $self = $_[0];
  while (@{$self->{wq} || []}) {
    my $q = shift @{$self->{wq}};
    if (@$q == 2) { # promise
      $q->[1]->("Canceled by failure of earlier write operations");
    }
  }
  delete $self->{rw};
  delete $self->{ww};
  delete $self->{wq};
  if (defined delete $self->{fh}) {
    AE::postpone { (delete $self->{cb})->($self, 'close') };
    $self->{cb_to_be_deleted} = 1;
  } else {
    delete $self->{cb} unless $self->{cb_to_be_deleted};
  }
} # _close

sub DESTROY ($) {
  $_[0]->abort (message => "Aborted by DESTROY of $_[0]");

  local $@;
  eval { die };
  warn "Reference to @{[ref $_[0]]} (@{[$_[0]->{id}]}) is not discarded before global destruction\n"
      if $@ =~ /during global destruction/;

} # DESTROY

1;

=head1 LICENSE

Copyright 2016 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
