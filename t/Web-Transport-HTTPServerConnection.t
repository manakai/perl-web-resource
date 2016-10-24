use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->child ('t_deps/lib');
use lib glob path (__FILE__)->parent->parent->child ('t_deps/modules/*/lib');
use Test::X1;
use Test::More;
use AnyEvent::Socket;
use Promised::Flow;
use Web::Host;
use Web::URL;
use Web::Transport::TCPTransport;
use Web::Transport::ConnectionClient;
use Web::Transport::HTTPServerConnection;

{
  use Socket;
  my $EphemeralStart = 1024;
  my $EphemeralEnd = 5000;

  sub is_listenable_port ($) {
    my $port = $_[0];
    return 0 unless $port;
    
    my $proto = getprotobyname('tcp');
    socket(my $server, PF_INET, SOCK_STREAM, $proto) || die "socket: $!";
    setsockopt($server, SOL_SOCKET, SO_REUSEADDR, pack("l", 1)) || die "setsockopt: $!";
    bind($server, sockaddr_in($port, INADDR_ANY)) || return 0;
    listen($server, SOMAXCONN) || return 0;
    close($server);
    return 1;
  } # is_listenable_port

  my $using = {};
  sub find_listenable_port () {
    for (1..10000) {
      my $port = int rand($EphemeralEnd - $EphemeralStart);
      next if $using->{$port}++;
      return $port if is_listenable_port $port;
    }
    die "Listenable port not found";
  } # find_listenable_port
}

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $origin = Web::URL->parse_string ("http://$host:$port");

  my $cb = sub {
    my ($self, $type) = @_;
    if ($type eq 'headers') {
      my $req = $_[2];
      my $path = $req->{target_url}->path;

      $self->send_response_headers
          ({status => 210, status_text => $self->{id}});
      $self->close_response;
    }
  }; # $cb

  my $con_cb = sub {
    my ($self, $type) = @_;
    if ($type eq 'startstream') {
      return $cb;
    }
  }; # $con_cb

  my $con;
  my $server = tcp_server $host, $port, sub {
    my $tcp = Web::Transport::TCPTransport->new
        (fh => $_[0],
         host => Web::Host->parse_string ($_[1]), port => $_[2]);
    my $x = Web::Transport::HTTPServerConnection->new
        (transport => $tcp, cb => $con_cb);
    $con ||= $x;
  }; # $server

  my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
  my $id;
  $client->request (path => [])->then (sub {
    my $res = $_[0];
    test {
      $id = $con->id;
      is $res->status, 210;
      like $res->status_text, qr{^\Q$id\E};
      is $res->header ('Connection'), undef;
    } $c;
    return $con->close_after_current_stream;
  })->then (sub {
    return $client->request (path => []);
  })->then (sub {
    my $res = $_[0];
    test {
      is $res->status, 210;
      unlike $res->status_text, qr{^\Q$id\E};
    } $c;
    return $client->close;
  })->then (sub {
    return $con->closed;
  })->then (sub {
    undef $server;
    done $c;
    undef $c;
  });
} n => 5, name => 'server closed after request/response';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $origin = Web::URL->parse_string ("http://$host:$port");

  my $response_header_sent;
  my $after_response_header = Promise->new (sub { $response_header_sent = $_[0] });

  my $cb = sub {
    my ($self, $type) = @_;
    if ($type eq 'headers') {
      my $req = $_[2];
      my $path = $req->{target_url}->path;
      if ($path eq '/404') {
        $self->send_response_headers
            ({status => 404, status_text => $self->{id}});
        $self->close_response;
      } else {
        $self->send_response_headers
            ({status => 210, status_text => $self->{id}});
        $response_header_sent->($self);
      }
    }
  }; # $cb

  my $con_cb = sub {
    my ($self, $type) = @_;
    if ($type eq 'startstream') {
      return $cb;
    }
  }; # $con_cb

  my $con;
  my $server = tcp_server $host, $port, sub {
    my $tcp = Web::Transport::TCPTransport->new
        (fh => $_[0],
         host => Web::Host->parse_string ($_[1]), port => $_[2]);
    my $x = Web::Transport::HTTPServerConnection->new
        (transport => $tcp, cb => $con_cb);
    $con ||= $x;
  }; # $server

  my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
  my $id;
  my $after_request = $client->request (path => []);
  $after_response_header->then (sub {
    my $stream = $_[0];
    promised_sleep (1)->then (sub {
      $stream->send_response_data (\"abcde");
      $stream->close_response;
    });
    return $con->close_after_current_stream;
  })->then (sub {
    return $after_request;
  })->then (sub {
    my $res = $_[0];
    test {
      $id = $con->id;
      is $res->status, 210;
      like $res->status_text, qr{^\Q$id\E};
      is $res->header ('Connection'), undef;
      is $res->body_bytes, "abcde";
    } $c;
  })->then (sub {
    return $client->request (path => ['404']);
  })->then (sub {
    my $res = $_[0];
    test {
      is $res->status, 404;
      unlike $res->status_text, qr{^\Q$id\E};
    } $c;
    return $client->close;
  })->then (sub {
    return $con->closed;
  })->then (sub {
    undef $server;
    done $c;
    undef $c;
  });
} n => 6, name => 'server closed during response';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $origin = Web::URL->parse_string ("http://$host:$port");

  my $response_header_sent;
  my $after_response_header = Promise->new (sub { $response_header_sent = $_[0] });

  my $cb = sub {
    my ($self, $type) = @_;
    if ($type eq 'headers') {
      my $req = $_[2];
      my $path = $req->{target_url}->path;
      if ($path eq '/404') {
        $self->send_response_headers
            ({status => 404, status_text => $self->{id}});
        $self->close_response;
      } else {
        $response_header_sent->($self);
      }
    }
  }; # $cb

  my $con_cb = sub {
    my ($self, $type) = @_;
    if ($type eq 'startstream') {
      return $cb;
    }
  }; # $con_cb

  my $con;
  my $server = tcp_server $host, $port, sub {
    my $tcp = Web::Transport::TCPTransport->new
        (fh => $_[0],
         host => Web::Host->parse_string ($_[1]), port => $_[2]);
    my $x = Web::Transport::HTTPServerConnection->new
        (transport => $tcp, cb => $con_cb);
    $con ||= $x;
  }; # $server

  my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
  my $id;
  my $after_request = $client->request (path => []);
  $after_response_header->then (sub {
    my $stream = $_[0];
    promised_sleep (1)->then (sub {
      $stream->send_response_headers
          ({status => 210, status_text => $stream->{id}});
      $stream->send_response_data (\"abcde");
      $stream->close_response;
    });
    return $con->close_after_current_stream;
  })->then (sub {
    return $after_request;
  })->then (sub {
    my $res = $_[0];
    test {
      $id = $con->id;
      is $res->status, 210;
      is $res->header ('Connection'), 'close';
      like $res->status_text, qr{^\Q$id\E};
      is $res->body_bytes, "abcde";
    } $c;
  })->then (sub {
    return $client->request (path => ['404']);
  })->then (sub {
    my $res = $_[0];
    test {
      is $res->status, 404;
      unlike $res->status_text, qr{^\Q$id\E};
    } $c;
    return $client->close;
  })->then (sub {
    return $con->closed;
  })->then (sub {
    undef $server;
    done $c;
    undef $c;
  });
} n => 6, name => 'server closed before response';

run_tests;

=head1 LICENSE

Copyright 2016 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
