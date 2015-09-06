package Transport::TLS;
use strict;
use warnings;
use Carp qw(croak);
use Scalar::Util qw(weaken);
use AnyEvent;
use Promise;
use Net::SSLeay;
use AnyEvent::TLS;

sub new_from_transport ($$) {
  return bless {transport => $_[1]}, $_[0];
} # new_from_transport

sub id ($) {
  return $_[0]->{transport}->id;
} # id

sub start ($$) {
  weaken (my $self = $_[0]);
  croak "Bad state" if $self->{starttls};
  $self->{cb} = $_[1];
  $self->{wq} = [];

  my $p = Promise->new (sub { $self->{starttls_done} = [$_[0], $_[1]] });
  $self->{transport}->start (sub {
    my $type = $_[1];
    if ($type eq 'readdata') {
      Net::SSLeay::BIO_write ($self->{_rbio}, ${$_[2]});
      $self->_tls;
    } elsif ($type eq 'readeof') {
      unless ($self->{read_closed}) {
        my $data = $_[2];
        $data->{failed} = 1;
        $data->{message} //= 'Underlying transport closed before TLS closure';
        AE::postpone { $self->{cb}->($self, 'readeof', $data) };
        $self->{read_closed} = 1;
        $self->_close if $self->{write_closed};
      } else {
        #warn join ' ', "transport readeof", %{$_[2]};
      }
    } elsif ($type eq 'writeeof') {
      unless ($self->{write_closed}) {
        my $data = $_[2];
        $data->{failed} = 1;
        $data->{message} //= 'Underlying transport closed before TLS closure';
        AE::postpone { $self->{cb}->($self, 'writeeof', $data) };
        $self->{write_closed} = 1;
        $self->_close if $self->{read_closed};
      } else {
        #warn join ' ', "transport writeeof", %{$_[2]};
      }
    } elsif ($type eq 'close') {
      my $data = $_[2];
      AE::postpone { (delete $self->{cb})->($self, 'close', $data) };
    }
  })->then (sub {
    $self->{tls_ctx} = AnyEvent::TLS->new;
    $self->{tls}     = my $tls = $self->{tls_ctx}->_get_session ('connect', $self, $self->{peername}); #XXX

    # MODE_ENABLE_PARTIAL_WRITE | MODE_ACCEPT_MOVING_WRITE_BUFFER
    Net::SSLeay::CTX_set_mode ($tls, 1 | 2);
    $self->{_rbio} = Net::SSLeay::BIO_new (Net::SSLeay::BIO_s_mem ());
    $self->{_wbio} = Net::SSLeay::BIO_new (Net::SSLeay::BIO_s_mem ());

    Net::SSLeay::set_bio ($tls, $self->{_rbio}, $self->{_wbio});

    $self->_tls;
  })->catch (sub {
    (delete $self->{starttls_done})->[1]->($_[0]);
  });

  $self->{starttls} = 1;
  return $p;
} # start

sub read_closed ($) { return $_[0]->{read_closed} }
sub write_closed ($) { return $_[0]->{write_closed} }
sub write_to_be_closed ($) { return $_[0]->{write_closed} || $_[0]->{write_shutdown} }

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
  $self->_tls;
} # push_write

sub push_promise ($) {
  my $self = $_[0];
  croak "Bad state" if not defined $self->{wq} or $self->{write_shutdown};
  my ($ok, $ng);
  my $p = Promise->new (sub { ($ok, $ng) = @_ });
  push @{$self->{wq}}, [$ok, $ng];
  $self->_tls;
  return $p;
} # push_promise

sub push_shutdown ($) {
  my $self = $_[0];
  croak "Bad state" if not defined $self->{wq} or $self->{write_shutdown};
  my ($ok, $ng);
  my $p = Promise->new (sub { ($ok, $ng) = @_ });
  push @{$self->{wq}}, [sub {
    Net::SSLeay::shutdown ($self->{tls});
    $self->{write_closed} = 1;
    AE::postpone { $self->{cb}->($self, 'writeeof', {}) };
    $ok->();
  }, $ng];
  $self->{write_shutdown} = 1;
  $self->_tls;
  return $p;
} # push_shutdown

use constant ERROR_SYSCALL => Net::SSLeay::ERROR_SYSCALL ();
use constant ERROR_WANT_READ => Net::SSLeay::ERROR_WANT_READ ();

sub _tls ($) {
  my ($self) = @_;

  while (@{$self->{wq}}) {
    my $w = shift @{$self->{wq}};
    if (@$w == 3) { # data
      my $r = Net::SSLeay::write ($self->{tls}, substr ${$w->[0]}, $w->[2], $w->[1]);
      if ($r <= 0) {
        $r = Net::SSLeay::get_error ($self->{tls}, $r);
        if ($r != ERROR_WANT_READ and $r != ERROR_SYSCALL) {
          my $data = {failed => 1};
          if ($r == ERROR_SYSCALL) {
            $data->{errno} = 0+$!;
            $data->{message} = "$!";
          } else {
            $data->{openssl_error} = Net::SSLeay::ERR_get_error ();
            $data->{message} = Net::SSLeay::ERR_error_string
                ($data->{openssl_error});
          }

          my $rc = $self->{read_closed};
          $self->{read_closed} = 1;
          $self->{write_closed} = 1;
          AE::postpone {
            $self->{cb}->($self, 'writeeof', $data);
            $self->{cb}->($self, 'readeof',
                          {failed => 1, message => 'Closed by write error'})
                unless $rc;
          };
          $self->_close;
          return;
        }

        unshift @{$self->{wq}}, $w;
        last;
      }
    } elsif (@$w == 2) { # promise
      $w->[0]->();
    } else {
      die "Bad wq data (l = @{[0+@$w]})";
    }
  } # $w

  while (defined (my $read = Net::SSLeay::read ($self->{tls}))) {
    if (length $read) {
      AE::postpone { $self->{cb}->($self, 'readdata', \$read) };
    } else { # EOF
      if (defined $self->{starttls_done}) {
        (delete $self->{starttls_done})->[1]->("TLS handshake failed");
      }
      unless ($self->{read_closed}) {
        $self->{read_closed} = 1;
        AE::postpone { $self->{cb}->($self, 'readeof', {}) };
      }
      last;
    }
  }
  {
    my $r = Net::SSLeay::get_error ($self->{tls}, -1); # -1 is not neccessarily correct, but Net::SSLeay doesn't tell us
    if ($r != ERROR_WANT_READ and $r != ERROR_SYSCALL) {
      my $data = {failed => 1};
      if ($r == ERROR_SYSCALL) {
        $data->{errno} = 0+$!;
        $data->{message} = "$!";
      } else {
        $data->{openssl_error} = Net::SSLeay::ERR_get_error ();
        $data->{message} = Net::SSLeay::ERR_error_string
            ($data->{openssl_error});
      }

      my $wc = $self->{write_closed};
      $self->{read_closed} = 1;
      $self->{write_closed} = 1;
      AE::postpone {
        $self->{cb}->($self, 'readeof', $data);
        $self->{cb}->($self, 'writeeof',
                      {failed => 1, message => 'Closed by read error'})
            unless $wc;
      };
      $self->_close;
      return;
    }
  }

  while (length (my $read = Net::SSLeay::BIO_read ($self->{_wbio}))) {
    $self->{transport}->push_write (\$read);
  }

  if (defined $self->{starttls_done}) {
    if (Net::SSLeay::state ($self->{tls}) == Net::SSLeay::ST_OK ()) {
      (delete $self->{starttls_done})->[0]->();
    }
  }
  $self->_close if $self->{read_closed} and $self->{write_closed};
} # _tls

sub abort ($) {
  my $self = $_[0];
  return unless defined $self->{wq};
  if (defined $self->{tls}) {
    Net::SSLeay::set_quiet_shutdown ($self->{tls}, 1);
    Net::SSLeay::shutdown ($self->{tls});
  }
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
  if (defined $self->{transport}) {
    $self->{transport}->push_shutdown
        unless $self->{transport}->write_to_be_closed;
    delete $self->{transport};
  }
  while (@{$self->{wq}}) {
    my $q = shift @{$self->{wq}};
    if (@$q == 2) { # promise
      $q->[1]->();
    }
  }
  delete $self->{wq};
  Net::SSLeay::free (delete $self->{tls}) if defined $self->{tls};
  delete $self->{_rbio};
  delete $self->{_wbio};
  delete $self->{tls_ctx};
  # $self->{cb} is not deleted by this method
} # _close

sub DESTROY ($) {
  $_[0]->abort;

  local $@;
  eval { die };
  warn "Possible memory leak detected (Transport::TLS)\n"
      if $@ =~ /during global destruction/;

} # DESTROY

1;

## <http://cpansearch.perl.org/src/MLEHMANN/AnyEvent-7.11/COPYING>
## > This module is licensed under the same terms as perl itself.
