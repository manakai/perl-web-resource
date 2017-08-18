use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->child ('t_deps/lib');
use lib glob path (__FILE__)->parent->parent->child ('t_deps/modules/*/lib');
use Promise;
use Promised::Flow;
use Test::X1;
use Test::More;
use AnyEvent::Socket;
use AnyEvent::Util qw(run_cmd);
use Web::URL;
use Web::Transport::BasicClient;
use Web::Transport::ConstProxyManager;
use Web::Transport::ProxyServerConnection;
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

sub psgi_server ($$;$%) {
  my $app = shift;
  my $cb = shift;
  my %args = @_;
  my $onexception = $args{onexception};
  return Promise->new (sub {
    my ($ok, $ng) = @_;
    my $cv = AE::cv;
    $cv->begin;
    my $host = '127.0.0.1';
    my $port = find_listenable_port;
    my $con;
    my $server = tcp_server $host, $port, sub {
      $cv->begin;
      $con = Web::Transport::PSGIServerConnection->new_from_app_and_ae_tcp_server_args
          ($app, [@_], parent_id => $args{parent_id});
      $con->{connection}->{server_header} = $args{server_name};
      $con->onexception ($onexception) if defined $onexception;
      if (exists $args{max}) {
        $con->max_request_body_length ($args{max});
      }
      promised_cleanup { $cv->end } $con->completed;
    };
    $cv->cb ($ok);
    my $origin = Web::URL->parse_string ("http://$host:$port");
    my $close = sub { undef $server; $cv->end };
    $cb->($origin, $close, \$con);
  });
} # psgi_server

my $server_pids = {};
END { kill 'KILL', $_ for keys %$server_pids }
sub _server_as_cv ($$$$) {
  my ($host, $addr, $port, $code) = @_;
  my $cv = AE::cv;
  my $started;
  my $pid;
  my $data = '';
  local $ENV{SERVER_HOST_NAME} = $host;
  run_cmd
      ['perl', path (__FILE__)->parent->parent->child ('t_deps/server.pl'), $addr, $port],
      '<' => \$code,
      '>' => sub {
        $data .= $_[0] if defined $_[0];
        return if $started;
        if ($data =~ /^\[server (\S+) (\S+)\]/m) {
          $cv->send ({pid => $pid, host => $host, addr => $1, port => $2,
                      stop => sub {
                        kill 'TERM', $pid;
                        delete $server_pids->{$pid};
                      }});
          $started = 1;
        }
      },
      '$$' => \$pid;
  $server_pids->{$pid} = 1;
  return $cv;
} # _server_as_cv

sub rawserver ($) {
  return Promise->from_cv (_server_as_cv ('localhost', '127.0.0.1', find_listenable_port, $_[0]));
} # rawserver

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_name = rand;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_ae_tcp_server_args ([@_]);
      promised_cleanup { $ok->() } $con->completed;
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  promised_cleanup {
    done $c; undef $c;
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    return [412, ['Hoge', 'foo', 'Fuga', $env->{HTTP_FUGA},
                  'Request-URL', $env->{REQUEST_URI},
                  'Request-Via', $env->{HTTP_VIA},
                  'Request-Method', $env->{REQUEST_METHOD},
                  'Request-Connection', $env->{HTTP_CONNECTION}], ['200!']];
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url);
    $client->proxy_manager ($pm);
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url, headers => {'Fuga' => 'a b'})->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 412;
        is $res->status_text, 'Precondition Failed';
        is $res->header ('Hoge'), 'foo';
        is $res->header ('Fuga'), 'a b';
        is $res->header ('Request-URL'), '/abc?d';
        is $res->header ('Via'), undef;
        is $res->header ('Request-Via'), '';
        is $res->header ('Request-Method'), 'GET';
        is $res->header ('Server'), $server_name;
        like $res->header ('Date'), qr/^\w+, \d\d \w+ \d+ \d\d:\d\d:\d\d GMT$/;
        is $res->header ('Connection'), undef;
        is $res->header ('Request-Connection'), 'keep-alive';
        is $res->header ('Transfer-Encoding'), 'chunked';
        is $res->body_bytes, '200!';
      } $c;
    });
  }, server_name => $server_name);
} n => 14, name => 'Basic request and response forwarding';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_ae_tcp_server_args ([@_]);
      promised_cleanup { $ok->() } $con->completed;
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  promised_cleanup {
    done $c; undef $c;
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    return [412, ['Hoge', 'foo'], ['200!']];
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url);
    $client->proxy_manager ($pm);
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url, headers => {'Fuga' => 'a b'})->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 412;
      } $c;
      return $client->request (url => $url, headers => {'Fuga' => 'a b'});
    })->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 412;
      } $c;
    });
  });
} n => 2, name => 'second request/response';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_ae_tcp_server_args ([@_]);
      promised_cleanup { $ok->() } $con->completed;
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  promised_cleanup {
    done $c; undef $c;
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    return [412, ['Hoge', 'foo'], ['200!']];
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url);
    $client->proxy_manager ($pm);
    my $req1 = $client->request (url => $url, headers => {'Fuga' => 'a b'});
    my $req2 = $client->request (url => $url, headers => {'Fuga' => 'a b'});
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $req1->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 412;
      } $c;
      return $req2;
    })->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 412;
      } $c;
    });
  });
} n => 2, name => 'second request/response';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_name = rand;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_ae_tcp_server_args ([@_]);
      $con->{connection}->{server_header} = $server_name;
      promised_cleanup { $ok->() } $con->completed;
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  promised_cleanup {
    done $c; undef $c;
    return $server_p;
  } Promise->resolve->then (sub {
    my $host = rand . 'foo.bar.test';
    my $port = 1024 + int rand 10000;
    my $url = Web::URL->parse_string (qq<http://$host:$port/abc?d>);
    my $client = Web::Transport::BasicClient->new_from_url ($url);
    $client->proxy_manager ($pm);
    promised_cleanup {
      $close_server->();
      return $client->close;
    } $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 503;
        is $res->status_text, 'Service Unavailable';
        is $res->header ('Via'), undef;
        is $res->header ('Server'), $server_name;
        like $res->header ('Date'), qr/^\w+, \d\d \w+ \d+ \d\d:\d\d:\d\d GMT$/;
        is $res->header ('Connection'), undef;
        is $res->header ('Transfer-Encoding'), 'chunked';
        is $res->body_bytes, '503';
      } $c;
    });
  });
} n => 8, name => 'bad remote host';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_name = rand;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_ae_tcp_server_args ([@_], server_header => $server_name);
      $con->{last_resort_timeout} = 3;
      promised_cleanup { $ok->() } $con->completed;
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $responder;
  promised_cleanup {
    done $c; undef $c;
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    return sub { $responder = $_[0] };
  }, sub {
    my ($origin, $close, $conref) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url);
    $client->proxy_manager ($pm);
    promised_cleanup {
      $close_server->();
      undef $responder;
      return $client->close->then ($close);
    } $client->request (url => $url, headers => {'Fuga' => 'a b'})->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 504;
        is $res->status_text, 'Gateway Timeout';
        is $res->header ('Via'), undef;
        is $res->header ('Server'), $server_name;
        like $res->header ('Date'), qr/^\w+, \d\d \w+ \d+ \d\d:\d\d:\d\d GMT$/;
        is $res->header ('Connection'), undef;
        is $res->header ('Transfer-Encoding'), 'chunked';
        is $res->body_bytes, '504';
      } $c;
    });
  });
} n => 8, name => 'remote host timeout';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_name = rand;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_ae_tcp_server_args ([@_], server_header => $server_name);
      promised_cleanup { $ok->() } $con->completed;
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  promised_cleanup {
    done $c; undef $c;
    return $server_p;
  } rawserver (q{
    receive "GET"
    close
  })->then (sub {
    my $server = $_[0];
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}/});
    my $client = Web::Transport::BasicClient->new_from_url ($url);
    $client->proxy_manager ($pm);
    promised_cleanup {
      $close_server->();
      return $client->close;
    } $client->request (url => $url, headers => {'Fuga' => 'a b'})->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 502;
        is $res->status_text, 'Bad Gateway';
        is $res->header ('Server'), $server_name;
        like $res->header ('Date'), qr/^\w+, \d\d \w+ \d+ \d\d:\d\d:\d\d GMT$/;
        is $res->header ('Connection'), undef;
        is $res->header ('Transfer-Encoding'), 'chunked';
        is $res->body_bytes, '502';
      } $c;
    });
  });
} n => 7, name => 'remote bad response';

# XXX remote 5xx
# XXX request body forwarding
# XXX client aborting
# XXX remote server aborting
# XXX server-level preprocessing hook
# XXX proxy authentication
# XXX request-target URL scheme restrictions
# XXX CONNECT support
# XXX WS proxying
# XXX option accessors
# XXX 407 from upstream
# XXX Connection: handling
# XXX https listening
# XXX unix listening
# XXX close_after_

run_tests;

=head1 LICENSE

Copyright 2016-2017 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
