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
use Web::Transport::PSGIServerConnection;

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

  my $app = sub {
    return [210, [], []];
  };

  my $con;
  my $server = tcp_server $host, $port, sub {
    my $x = Web::Transport::PSGIServerConnection
        ->new_from_app_and_ae_tcp_server_args ($app, [@_]);
    $con ||= $x;
  }; # $server

  my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
  my $id;
  $client->request (path => [])->then (sub {
    my $res = $_[0];
    test {
      $id = $con->id;
      is $res->status, 210;
      #like $res->status_text, qr{^\Q$id\E};
      is $res->header ('Connection'), undef;
      ok ! $res->incomplete;
    } $c;
    return $con->close_after_current_response;
  })->then (sub {
    return $client->request (path => []);
  })->then (sub {
    my $res = $_[0];
    test {
      is $res->status, 210;
      #unlike $res->status_text, qr{^\Q$id\E};
    } $c;
    return $client->close;
  })->then (sub {
    return $con->closed;
  })->then (sub {
    undef $server;
    done $c;
    undef $c;
  });
} n => 4, name => 'server closed after request/response';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $origin = Web::URL->parse_string ("http://$host:$port");

  my $response_header_sent;
  my $after_response_header = Promise->new (sub { $response_header_sent = $_[0] });

  my $app = sub {
    my $env = $_[0];
    return sub {
      my $path = $env->{REQUEST_URI};
      if ($path eq '/404') {
        $_[0]->([404, [], []]);
      } else {
        my $w = $_[0]->([210, []]);
        $response_header_sent->($w);
        undef $response_header_sent;
      }
    };
  }; # $app

  my $con;
  my $server = tcp_server $host, $port, sub {
    my $x = Web::Transport::PSGIServerConnection
        ->new_from_app_and_ae_tcp_server_args ($app, [@_]);
    $con ||= $x;
  }; # $server

  my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
  my $id;
  my $after_request = $client->request (path => []);
  $after_response_header->then (sub {
    my $w = $_[0];
    promised_sleep (1)->then (sub {
      $w->write ("abcde");
      $w->close;
    });
    return $con->close_after_current_response;
  })->then (sub {
    return $after_request;
  })->then (sub {
    my $res = $_[0];
    test {
      $id = $con->id;
      is $res->status, 210;
      #like $res->status_text, qr{^\Q$id\E};
      is $res->header ('Connection'), undef;
      is $res->body_bytes, "abcde";
      ok ! $res->incomplete;
    } $c;
  })->then (sub {
    return $client->request (path => ['404']);
  })->then (sub {
    my $res = $_[0];
    test {
      is $res->status, 404;
      #unlike $res->status_text, qr{^\Q$id\E};
    } $c;
    return $client->close;
  })->then (sub {
    return $con->closed;
  })->then (sub {
    undef $server;
    done $c;
    undef $c;
  });
} n => 5, name => 'server closed during response';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $origin = Web::URL->parse_string ("http://$host:$port");

  my $response_header_sent;
  my $after_response_header = Promise->new (sub { $response_header_sent = $_[0] });

  my $app = sub {
    my $env = $_[0];
    return sub {
      my $path = $env->{REQUEST_URI};
      if ($path eq '/404') {
        $_[0]->([404, [], []]);
      } else {
        $response_header_sent->($_[0]);
      }
    }
  }; # $app

  my $con;
  my $server = tcp_server $host, $port, sub {
    my $x = Web::Transport::PSGIServerConnection
        ->new_from_app_and_ae_tcp_server_args ($app, [@_]);
    $con ||= $x;
  }; # $server

  my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
  my $id;
  my $after_request = $client->request (path => []);
  $after_response_header->then (sub {
    my $responder = $_[0];
    promised_sleep (1)->then (sub {
      my $w = $responder->([210, []]);
      $w->write ("abcde");
      $w->close;
    });
    return $con->close_after_current_response;
  })->then (sub {
    return $after_request;
  })->then (sub {
    my $res = $_[0];
    test {
      $id = $con->id;
      is $res->status, 210;
      is $res->header ('Connection'), 'close';
      #like $res->status_text, qr{^\Q$id\E};
      is $res->body_bytes, "abcde";
      ok ! $res->incomplete;
    } $c;
  })->then (sub {
    return $client->request (path => ['404']);
  })->then (sub {
    my $res = $_[0];
    test {
      is $res->status, 404;
      #unlike $res->status_text, qr{^\Q$id\E};
    } $c;
    return $client->close;
  })->then (sub {
    return $con->closed;
  })->then (sub {
    undef $server;
    done $c;
    undef $c;
  });
} n => 5, name => 'server closed before response';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $origin = Web::URL->parse_string ("http://$host:$port");

  my $response_header_sent;
  my $after_response_header = Promise->new (sub { $response_header_sent = $_[0] });

  my $psgi_cv;
  my $app = sub {
    my $env = $_[0];
    return sub {
      my $path = $env->{REQUEST_URI};
      if ($path eq '/404') {
        $_[0]->([404, [], []]);
      } else {
        my $w = $_[0]->([210, []]);
        $response_header_sent->($w);
        undef $response_header_sent;
        $psgi_cv = $env->{'psgix.exit_guard'};
        $psgi_cv->begin;
      }
    };
  }; # $app

  my $con;
  my @con;
  my $server = tcp_server $host, $port, sub {
    my $x = Web::Transport::PSGIServerConnection
        ->new_from_app_and_ae_tcp_server_args ($app, [@_]);
    $con ||= $x;
    push @con, $x;
  }; # $server

  my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
  my $id;
  my $after_request = $client->request (path => []);
  my $after_abort = 0;
  $after_response_header->then (sub {
    my $w = $_[0];
    promised_sleep (1)->then (sub {
      $w->write ("abcde");
      #$w->close;
      return promised_sleep (3)->then (sub {
        $after_abort = 1;
        $psgi_cv->end;
        undef $w;
      });
    });
    return $con->close_after_current_response (timeout => 2);
  })->then (sub {
    return $after_request;
  })->then (sub {
    my $res = $_[0];
    test {
      $id = $con->id;
      is $res->status, 210;
      #like $res->status_text, qr{^\Q$id\E};
      is $res->header ('Connection'), undef;
      is $res->body_bytes, "abcde";
      ok $res->incomplete;
    } $c;
  })->then (sub {
    return $client->request (path => ['404']);
  })->then (sub {
    my $res = $_[0];
    test {
      is $res->status, 404, "next connection's response";
      #unlike $res->status_text, qr{^\Q$id\E};
    } $c;
    return $client->close;
  })->then (sub {
    return Promise->all ([map { $_->completed } @con]);
  })->then (sub {
    test {
      ok $after_abort, "after abort";
    } $c;
    undef $server;
    done $c;
    undef $c;
  });
} n => 6, name => 'server closed by aborting with timeout';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $origin = Web::URL->parse_string ("http://$host:$port");

  my $response_header_sent;
  my $after_response_header = Promise->new (sub { $response_header_sent = $_[0] });

  my $psgi_cv;
  my $app = sub {
    my $env = $_[0];
    return sub {
      my $path = $env->{REQUEST_URI};
      if ($path eq '/404') {
        $_[0]->([404, [], []]);
      } else {
        my $w = $_[0]->([210, []]);
        $response_header_sent->($w);
        undef $response_header_sent;
        $psgi_cv = $env->{'psgix.exit_guard'};
        $psgi_cv->begin;
      }
    };
  }; # $app

  my $con;
  my @con;
  my $server = tcp_server $host, $port, sub {
    my $x = Web::Transport::PSGIServerConnection
        ->new_from_app_and_ae_tcp_server_args ($app, [@_]);
    $con ||= $x;
    push @con, $x;
  }; # $server

  my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
  my $id;
  my $after_request = $client->request (path => []);
  my $after_abort = 0;
  $after_response_header->then (sub {
    my $w = $_[0];
    promised_sleep (1)->then (sub {
      $w->write ("abcde");
      $w->close; # ! close here
      return promised_sleep (3)->then (sub {
        $after_abort = 1;
        $psgi_cv->end;
        undef $w;
      });
    });
    return $con->close_after_current_response (timeout => 2);
  })->then (sub {
    return $after_request;
  })->then (sub {
    my $res = $_[0];
    test {
      $id = $con->id;
      is $res->status, 210;
      #like $res->status_text, qr{^\Q$id\E};
      is $res->header ('Connection'), undef;
      is $res->body_bytes, "abcde";
      ok ! $res->incomplete;
    } $c;
  })->then (sub {
    return $client->request (path => ['404']);
  })->then (sub {
    my $res = $_[0];
    test {
      is $res->status, 404, "next connection's response";
      #unlike $res->status_text, qr{^\Q$id\E};
    } $c;
    return $client->close;
  })->then (sub {
    return Promise->all ([map { $_->completed } @con]);
  })->then (sub {
    test {
      ok $after_abort, "after abort";
    } $c;
    undef $server;
    done $c;
    undef $c;
  });
} n => 6, name => 'server closed by aborting with timeout 2';

run_tests;

=head1 LICENSE

Copyright 2016 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
