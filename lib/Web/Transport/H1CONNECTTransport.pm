package Web::Transport::H1CONNECTTransport;
use strict;
use warnings;
our $VERSION = '1.0';
require utf8;
use Carp qw(croak);
use AnyEvent;
use Promise;

sub new ($%) {
  my $self = bless {}, shift;
  my $args = $self->{args} = {@_};
  $self->{http} = delete $self->{args}->{http};
  $self->{id} = $self->{http}->id . 'C';
  croak "Bad |target|" unless defined $args->{target};
  croak "utf8-flagged |target|" if utf8::is_utf8 $args->{target};
  return $self;
} # new

sub start ($$) {
  my $self = $_[0];
  croak "Bad state" if not defined $self->{args};
  $self->{cb} = $_[1];
  my $args = delete $self->{args};

  my ($ok, $ng);
  my $p = Promise->new (sub { ($ok, $ng) = @_ });

  my $req = {method => 'CONNECT',
             target => $args->{target},
             headers => [[Host => $args->{target}],
                         ['Proxy-Connection' => 'keep-alive']]};
  push @{$req->{headers}}, ['User-Agent', 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.87 Safari/537.36']; # XXX

  # XXX headers
  my $onevent = sub {
    my $type = $_[1];
    if ($type eq 'data' and $self->{started}) {
      my $data = $_[2]; # string copy!
      AE::postpone { $self->{cb}->($self, 'readdata', \$data) };
    } elsif ($type eq 'dataend' and $self->{started}) {
      unless ($self->{read_closed}) {
        $self->{read_closed} = 1;
        AE::postpone { $self->{cb}->($self, 'readeof', {}) };
      }
    } elsif ($type eq 'headers') {
      my $res = $_[2];
      if ($res->{status} == 200) {
        AE::postpone { $self->{cb}->($self, 'open') };
        $self->{info} = {};
        $ok->({response => $res});
        $self->{started} = 1;
      } else {
        $self->{info} = {};
        $ng->({failed => 1, message => "HTTP |$res->{status}| response",
               response => $res});
      }
    } elsif ($type eq 'complete') {
      my $exit = $_[2];
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
        } else {
          $self->{info} = {};
          $ng->($exit);
        }
      }
      $self->{http}->close->then (sub {
        if ($self->{started}) {
          AE::postpone { (delete $self->{cb})->($self, 'close') };
        } else {
          delete $self->{cb};
        }
        delete $self->{http};
      });
    }
  }; # $onevent
  $self->{http}->connect->then (sub {
    return $self->{http}->send_request_headers ($req, cb => $onevent);
  })->catch (sub {
    $self->{info} = {};
    $ng->($_[0]);
    delete $self->{cb} unless $self->{started};
    delete $self->{http};
  });
  return $p;
} # start

sub id ($) { return $_[0]->{id} }
sub type ($) { return 'H1CONNECT' }
sub layered_type ($) { return $_[0]->type . '/' . $_[0]->{http}->layered_type }
sub request_mode ($) { 'default' }
sub info ($) { return $_[0]->{info} } # or undef

sub read_closed ($) { return $_[0]->{read_closed} }
sub write_closed ($) { return $_[0]->{write_closed} }
sub write_to_be_closed ($) { return $_[0]->{write_closed} || $_[0]->{write_shutdown} }

sub push_write ($$;$$) {
  my ($self, $ref, $offset, $length) = @_;
  croak "Bad state" if defined $self->{args} or $self->{write_shutdown};
  croak "Data is utf8-flagged" if utf8::is_utf8 $$ref;
  $offset = 0 unless defined $offset;
  croak "Bad offset" if $offset > length $$ref;
  $length = (length $$ref) - $offset unless defined $length;
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
  $self->{write_shutdown} = 1;
  if (defined $self->{http}) {
    $self->{http}->abort (%args);
  }
} # abort

sub DESTROY ($) {
  $_[0]->abort (message => "Aborted by DESTROY of $_[0]");

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
