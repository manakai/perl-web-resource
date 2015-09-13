package Transport::H1CONNECT;
use strict;
use warnings;
use Carp qw(croak);
use AnyEvent;
use Promise;

sub new ($%) {
  my $self = bless {}, shift;
  $self->{args} = {@_};
  $self->{http} = delete $self->{args}->{http};
  $self->{id} = $self->{http}->id . 'C';
  return $self;
} # new

sub start ($$) {
  my $self = $_[0];
  croak "Bad state" if not defined $self->{args};
  $self->{cb} = $_[1];
  my $args = delete $self->{args};
  croak "Bad |host_name|" unless defined $args->{host_name};
  croak "utf8-flagged |host_name|" if utf8::is_utf8 $args->{host_name};
  my $host = $args->{host_name};
  if (defined $args->{port}) {
    croak "utf8-flagged |port|" if utf8::is_utf8 $args->{port};
    $host .= ':' . $args->{port};
  }

  my ($ok, $ng);
  my $p = Promise->new (sub { ($ok, $ng) = @_ });

  my $req = {method => 'CONNECT',
             target => $host};
  # XXX headers
  $self->{http}->onevent (sub {
    my $type = $_[2];
    if ($type eq 'data') {
      my $data = $_[3];
      AE::postpone { $self->{cb}->($self, 'readdata', \$data) };
    } elsif ($type eq 'dataend') {
      unless ($self->{read_closed}) {
        $self->{read_closed} = 1;
        AE::postpone { $self->{cb}->($self, 'readeof', {}) };
      }
    } elsif ($type eq 'headers') {
      my $res = $_[3];
      if ($res->{status} == 200 and $res->{version} ne '0.9') {
        $ok->({response => $res});
        $self->{started} = 1;
      } else {
        $ng->({response => $res});
      }
    } elsif ($type eq 'complete') {
      my $exit = $_[3];
      if ($exit->{failed}) {
        if ($self->{started}) {
          unless ($self->{read_closed}) {
            $self->{read_closed} = 1;
            AE::postpone { $self->{cb}->($self, 'readeof', $exit) };
          }
          unless ($self->{write_closed}) {
            $self->{write_closed} = 1;
            AE::postpone { $self->{cb}->($self, 'writeeof', $exit) };
          }
        }
        $ng->({exit => $exit});
      }
      AE::postpone { (delete $self->{cb})->($self, 'close', {}) };
      delete $self->{http};
    }
  });
  $self->{http}->connect->then (sub {
    return $self->{http}->send_request_headers ($req);
  })->catch (sub {
    $ng->($_[0]);
    delete $self->{cb};
  });
  return $p;
} # start

sub id ($) { return $_[0]->{id} }
sub type ($) { return 'H1CONNECT' }
sub layered_type ($) { return $_[0]->type . '/' . $_[0]->{http}->layered_type }

sub read_closed ($) { return $_[0]->{read_closed} }
sub write_closed ($) { return $_[0]->{write_closed} }
sub write_to_be_closed ($) { return $_[0]->{write_closed} || $_[0]->{write_shutdown} }

sub push_write ($$;$$) {
  my ($self, $ref, $offset, $length) = @_;
  croak "Bad state" if defined $self->{args} or $self->{write_shutdown};
  croak "Data is utf8-flagged" if utf8::is_utf8 $$ref;
  $offset //= 0;
  croak "Bad offset" if $offset > length $$ref;
  $length //= (length $$ref) - $offset;
  croak "Bad length" if $offset + $length > length $$ref;
  $self->{http}->send_data (\substr $$ref, $offset, $length);
} # push_write

sub push_promise ($) {
  my $self = $_[0];
  croak "Bad state" if defined $self->{args} or $self->{write_shutdown};
  return Promise->resolve;
} # push_promise

sub push_shutdown ($) {
  my $self = $_[0];
  croak "Bad state" if defined $self->{args} or $self->{write_shutdown};
  AE::postpone { $self->{cb}->($self, 'writeeof', {}) };
  $self->{write_closed} = 1;
  $self->{write_shutdown} = 1;
  $self->{http}->close;
  return Promise->resolve;
} # push_shutdown

sub abort ($;%) {
  my ($self, %args) = @_;
  delete $self->{args};
  my $wc = $self->{write_closed};
  my $rc = $self->{read_closed};
  $self->{write_closed} = 1;
  $self->{read_closed} = 1;
  $self->{write_shutdown} = 1;
  my $reason = $args{message} // 'Aborted';
  AE::postpone {
    $self->{cb}->($self, 'writeeof', {failed => 1, message => $reason})
        unless $wc;
    $self->{cb}->($self, 'readeof', {failed => 1, message => $reason})
        unless $rc;
  } unless $wc and $rc;
  if (defined $self->{http}) {
    $self->{http}->abort (%args);
    delete $self->{http};
  }
  return undef;
} # abort

sub DESTROY ($) {
  $_[0]->abort (message => "Aborted by DESTROY of $_[0]");

  local $@;
  eval { die };
  warn "Reference to Transport::H1CONNECT is not discarded before global destruction\n"
      if $@ =~ /during global destruction/;
} # DESTROY

1;
