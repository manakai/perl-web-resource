package Transport::TCP;
use strict;
use warnings;
use Carp qw(croak);
use Errno qw(EAGAIN EWOULDBLOCK EINTR);
use Socket qw(IPPROTO_TCP TCP_NODELAY SOL_SOCKET SO_KEEPALIVE SO_OOBINLINE);
use AnyEvent::Util qw(WSAEWOULDBLOCK);
use Promise;

sub new_from_fh_and_cb ($$$) {
  my $self = bless {fh => $_[1], cb => $_[2]}, $_[0];

  $self->{id} = int rand 100000;

  my $fh = $self->{fh};
  setsockopt $fh, SOL_SOCKET, SO_OOBINLINE, 0;
  setsockopt $fh, IPPROTO_TCP, TCP_NODELAY, 1;
  setsockopt $fh, SOL_SOCKET, SO_KEEPALIVE, 1;
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
        AE::postpone { $self->{cb}->($self, 'readeof', {}) };
        $self->_close if $self->{write_closed};
      }
    } elsif ($! != EAGAIN && $! != EINTR && $! != EWOULDBLOCK && $! != WSAEWOULDBLOCK) {
      my $wc = $self->{write_closed};
      $self->{read_closed} = 1;
      $self->{write_closed} = 1;
      delete $self->{rw};
      AE::postpone {
        $self->{cb}->($self, 'readeof', {failed => 1,
                                         errno => 0+$!,
                                         message => "$!"});
        $self->{cb}->($self, 'writeeof', {failed => 1,
                                          message => 'Closed by read error'})
            unless $wc;
      };
      $self->_close;
    }
  }; # $self->{rw}

  return $self;
} # new_from_fh_and_cb

sub id ($) { return $_[0]->{id} }

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
          AE::postpone {
            $self->{cb}->($self, 'writeeof', {failed => 1,
                                              errno => 0+$!,
                                              message => "$!"});
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
  $run->();

  $self->{ww} = AE::io $self->{fh}, 1, sub {
    $run->();
  } if defined $self->{wq} and @{$self->{wq}};
} # _start_write

sub push_write ($$;$$) {
  my ($self, $ref, $offset, $length) = @_;
  croak "Bad state" if not defined $self->{wq} or $self->{write_shutdown};
  croak "Data is utf8-flagged" if utf8::is_utf8 $$ref;
  $offset //= 0;
  croak "Bad offset" if $offset > length $$ref;
  $length //= (length $$ref) - $offset;
  croak "Bad length" if $offset + $length > length $$ref;
  return if $length <= 0;
  push @{$self->{wq}}, [$ref, $length, $offset];
  $self->_start_write;
} # push_write

sub push_promise ($) {
  my $self = $_[0];
  croak "Bad state" if not defined $self->{wq} or $self->{write_shutdown};
  my ($ok, $ng);
  my $p = Promise->new (sub { ($ok, $ng) = @_ });
  push @{$self->{wq}}, [$ok, $ng];
  $self->_start_write;
  return $p;
} # push_promise

sub push_shutdown ($) {
  my $self = $_[0];
  croak "Bad state" if not defined $self->{wq} or $self->{write_shutdown};
  my ($ok, $ng);
  my $p = Promise->new (sub { ($ok, $ng) = @_ });
  push @{$self->{wq}}, [sub {
    shutdown $self->{fh}, 1;
    $self->{write_closed} = 1;
    AE::postpone { $self->{cb}->($self, 'writeeof', {}) };
    $self->_close if $self->{read_closed};
    $ok->();
  }, $ng];
  $self->{write_shutdown} = 1;
  $self->_start_write;
  return $p;
} # push_shutdown

sub abort ($) {
  my $self = $_[0];
  return unless defined $self->{wq};
  shutdown $self->{fh}, 2 if defined $self->{fh};
  my $wc = $self->{write_closed};
  my $rc = $self->{read_closed};
  $self->{write_closed} = 1;
  $self->{read_closed} = 1;
  $self->{write_shutdown} = 1;
  AE::postpone {
    $self->{cb}->($self, 'writeeof', {failed => 1, message => 'Aborted'})
        unless $wc;
    $self->{cb}->($self, 'readeof', {failed => 1, message => 'Aborted'})
        unless $rc;
  };
  $self->_close;
} # abort

sub _close ($$) {
  my $self = $_[0];
  while (@{$self->{wq}}) {
    my $q = shift @{$self->{wq}};
    if (@$q == 2) { # promise
      $q->[1]->();
    }
  }
  delete $self->{rw};
  delete $self->{ww};
  delete $self->{wq};
  if (defined delete $self->{fh}) {
    AE::postpone { (delete $self->{cb})->($self, 'close') }
  } else {
    delete $self->{cb};
  }
} # _close

sub DESTROY ($) {
  $_[0]->abort;

  local $@;
  eval { die };
  warn "Possible memory leak detected (Transport::TCP)\n"
      if $@ =~ /during global destruction/;

} # DESTROY

1;
