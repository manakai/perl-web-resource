use strict;
use warnings;
use AnyEvent::Socket;
use Web::Transport::TCPTransport;

my $host = 0;
my $port = 8522;

my $server = tcp_server $host, $port, sub {
  my ($fh, $client_host, $client_port) = @_;
  warn "$client_host / $client_port";

  my $transport = Web::Transport::TCPTransport->new (fh => $fh);
  my $self = bless {transport => $transport,
                    rbuf => '', state => 'before request-line'}, 'Hoge'; # XXX space
  my $p = $transport->start (sub {
    my ($transport, $type) = @_;
    if ($type eq 'readdata') {
      $self->_ondata ($_[2]);
    } elsif ($type eq 'readeof') {
      $self->_oneof ($_[2]);
    } elsif ($type eq 'writeeof') {
      #warn "Sent EOF";
      #warn scalar gmtime;
    } elsif ($type eq 'close') {
      #warn "Closed";
      #warn scalar gmtime;
    }
  })->then (sub {
    warn "Established";
    warn scalar gmtime;
  });
};

AE::cv->recv;

package Hoge;

sub _ondata ($$) {
  my ($self, $inref) = @_;
  while (1) {
    if ($self->{state} eq 'before request-line') {
      $self->{rbuf} .= $$inref;
      if ($self->{rbuf} =~ s/\A([^\x0A]*)\x0A//) {
        my $line = $1;
        $line =~ s/\x0D\z//;
        my $method;
        my $version;
        if ($line =~ s{[\x09\x20]+HTTP/(1\.[01])\z}{}) {
          $version = $1;
        }
        if ($line =~ s{\A([^\x09\x20]+)[\x09\x20]+}{}) {
          $method = $1;
        }
        if (not defined $version) {
      unless ($method eq 'GET') {
        return $self->_fatal ($version);
      }
      $self->{request} = {version => $version, method => $method,
                          target => $line, headers => []};
      $self->onrequest ($self->{request});
    } else {
      return $self->_fatal ($version) unless length $line;
      $self->{request} = {version => $version, method => $method,
                          target => $line, headers => []};
      $self->{state} = 'before request header';
    }
    } else {
      return;
    }
  # XXX if rbuf is too long
  } elsif ($self->{state} eq 'before request header') {
    $self->{rbuf} .= $$inref;
    if ($self->{rbuf} =~ s/\A([^:\x0A]+):([^\x0A]*)\x0A//) {
      my $name = $1;
      my $value = $2;
      $value =~ s/\x0D\z//;
      push @{$self->{request}->{headers}}, [$name, $value];
    } elsif ($self->{rbuf} =~ s/\A\x0D?\x0A//) {
      my @length;
      for (@{$self->{request}->{headers}}) {
        my $n = $_->[0];
        $n =~ tr/A-Z/a-z/; ## ASCII case-insensitive
        if ($n eq 'content-length') {
          push @length, $n;
        }
      }
      # XXX if transfer-encoding
      if (@length == 1 and $length[0] =~ /\A[0-9]+\z/) {
        my $l = 0+$length[0];
        $self->{request}->{body_length} = $l;
        $self->{unread_length} = $l;
        $self->onrequest ($self->{request});
        if ($l == 0) {
          $self->_next;
        } else {
          $self->{state} = 'request body';
        }
      } else {
        $self->onrequest ($self->{request});
        $self->_next;
      }


  # XXX length=0 tests
  # XXX wrapped

      } elsif ($self->{rbuf} =~ s/\A[^\x0A]*\x0A//) {
        return $self->_fatal ($self->{request}->{version});
      } else {
        return;
      }
  # XXX bad name
  # XXX spaces
  # XXX if rbuf is too long

    } elsif ($self->{state} eq 'request body') {
      my $in_length = length $$inref;
      if ($self->{unread_length} == $in_length) {
        $self->ondata ($$inref);
        $self->onreof ({});
        $self->_next;
      } elsif ($self->{unread_length} < $in_length) {
        $self->ondata (substr ($$inref, 0, $self->{unread_length}));
        $self->onreof ({});
        $self->_next;
        # XXX and next is 400 error
      } else { # unread_length > $in_length
        $self->ondata ($$inref);
        $self->{unread_length} -= $in_length;
        return;
      }
    } else {
      die "Bad state |$self->{state}|";
    }
    $inref = \'';
  } # while
} # _ondata

sub _oneof ($$) {
  my ($self, $exit) = @_;
  if ($self->{state} eq 'before request-line') {
    return $self->_fatal (0.9);
  } elsif ($self->{state} eq 'before request header') {
    return $self->_fatal ($self->{request}->{version});
  } elsif ($self->{state} eq 'request body') {
    # $self->{unread_length} > 0
    $self->{request}->{incomplete} = 1;
    $self->onreof ($exit->{failed} ? $exit : {failed => 1, message => "Connection closed"});
    $self->_next;
  } else {
    die "Bad state |$self->{state}|";
  }
} # _oneof

sub _next ($) {
  my $self = $_[0];
  $self->{rbuf} = '';
  delete $self->{unread_length};
  $self->{state} = 'before request-line'; # XXX space
} # _next

sub _fatal ($$) {
  my ($self, $version) = @_;
  my $res = q{<!DOCTYPE html><html>
<head><title>400 Bad Request</title></head>
<body>400 Bad Request</body>
</html>};
  if ($version != 0.9) {
    $res = qq{HTTP/1.1 400 Bad Request\x0D
Server: XXX\x0D
Date: XXX\x0D
Content-Type: text/html; charset=utf-8\x0D
Content-Length: @{[length $res]}\x0D
Connection: close\x0D
\x0D
} . $res;
  }
  return $res;
} # _fatal

sub onrequest ($$) {
  my ($self, $request) = @_;
  AE::postpone {
    if ($request->{target} eq '/end') {
      $self->{transport}->push_write (\q{<html>200 Goodbye!</html>
});
      AE::postpone { exit };
    } elsif ($request->{method} eq 'GET') {
      $self->{transport}->push_write (\q{<html>...404 Not Found</html>
});
    } else {
      $self->{transport}->push_write (\q{<html>...405 Not Allowed</html>
});
    }
    $self->{transport}->push_shutdown;
  };
} # onrequest

sub ondata ($$) {
  warn "Server received [[$_[1]]]";
} # ondata

sub onreof ($$) {
  warn "End of request";
} # onreof
