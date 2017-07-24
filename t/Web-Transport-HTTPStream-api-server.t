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
use Web::Transport::ConnectionClient;
use Web::Transport::TCPStream;
use Web::Transport::HTTPStream;

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

sub d ($) {
  return DataView->new (ArrayBuffer->new_from_scalarref (\($_[0])));
} # d

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $origin = Web::URL->parse_string ("http://$host:$port");

  my $con;
  my $server = tcp_server $host, $port, sub {
    my $x = Web::Transport::HTTPStream->new_XXXserver
        ({parent => {
           class => 'Web::Transport::TCPStream',
           server => 1,
           fh => $_[0],
           host => Web::Host->parse_string ($_[1]), port => $_[2],
         }});
    my $r = $x->received_streams->get_reader;
    $r->read->then (sub {
      return 0 if $_[0]->{done};
      my $stream = $_[0]->{value};
      return $stream->request_ready->then (sub {
        my $path = $stream->{request}->{target_url}->path;

        $stream->send_response
            ({status => 210, status_text => $stream->{id}})->then (sub {
          return $stream->{response}->{body}->get_writer->close;
        });
      })->then (sub { return 1 });
    });

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
      if ($res->is_network_error) {
        ok $res->is_reset_error;
        ok 1;
      } else {
        is $res->status, 210, $res;
        unlike $res->status_text, qr{^\Q$id\E};
      }
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

  my $con;
  my $server = tcp_server $host, $port, sub {
    my $x = Web::Transport::HTTPStream->new_XXXserver
        ({parent => {
           class => 'Web::Transport::TCPStream',
           server => 1,
           fh => $_[0],
           host => Web::Host->parse_string ($_[1]), port => $_[2],
         }});
    $x->received_streams->get_reader->read->then (sub {
      return if $_[0]->{done};
      my $stream = $_[0]->{value};
      return $stream->request_ready->then (sub {
        my $path = $stream->{request}->{target_url}->path;
        if ($path eq '/404') {
          $stream->send_response
              ({status => 404, status_text => $stream->{id}})->then (sub {
            return $stream->{response}->{body}->get_writer->close;
          });
        } else {
          $stream->send_response
              ({status => 210, status_text => $stream->{id}})->then (sub {
            $response_header_sent->($stream);
          });
        }
      });
    });

    $con ||= $x;
  }; # $server

  my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
  my $id;
  my $after_request = $client->request (path => []);
  $after_response_header->then (sub {
    my $stream = $_[0];
    promised_sleep (1)->then (sub {
      my $w = $stream->{response}->{body}->get_writer;
      $w->write (d "abcde");
      return $w->close;
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

  my $con;
  my $server = tcp_server $host, $port, sub {
    my $x = Web::Transport::HTTPStream->new_XXXserver
        ({parent => {
           class => 'Web::Transport::TCPStream',
           server => 1,
           fh => $_[0],
           host => Web::Host->parse_string ($_[1]), port => $_[2],
         }});
    $x->received_streams->get_reader->read->then (sub {
      return if $_[0]->{done};
      my $stream = $_[0]->{value};
      return $stream->request_ready->then (sub {
        my $path = $stream->{request}->{target_url}->path;
        if ($path eq '/404') {
          $stream->send_response
              ({status => 404, status_text => $stream->{id}})->then (sub {
            return $stream->{response}->{body}->get_writer->close;
          });
        } else {
          $response_header_sent->($stream);
        }
      });
    });
    $con ||= $x;
  }; # $server

  my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
  my $id;
  my $after_request = $client->request (path => []);
  $after_response_header->then (sub {
    my $stream = $_[0];
    promised_sleep (1)->then (sub {
      return $stream->send_response
          ({status => 210, status_text => $stream->{id}})->then (sub {
        my $w = $stream->{response}->{body}->get_writer;
        $w->write (d "abcde");
        return $w->close;
      });
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

Copyright 2016-2017 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
