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
use Web::Transport::TCPTransport;
use Test::Certificates;

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

{
  package TLSTestResolver;
  sub new {
    return bless {host => $_[1]}, $_[0];
  }
  sub resolve ($$) {
    return Promise->resolve (Web::Host->parse_string ($_[0]->{host}));
  }
}

sub psgi_server ($$;%) {
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
          ($app, [@_], parent_id => $args{parent_id}, server_header => $args{server_name});
      $con->onexception ($onexception) if defined $onexception;
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

sub rawclient ($$$) {
  my ($host, $port, $input) = @_;
  my $tcp = Web::Transport::TCPTransport->new (host => $host, port => $port);
  my $data = '';
  my $p = Promise->new (sub {
    my $ok = $_[0];
    $tcp->start (sub {
      my ($self, $type) = @_;
      if ($type eq 'readdata') {
        $data .= ${$_[2]};
      } elsif ($type eq 'readeof') {
        $tcp->push_shutdown;
      } elsif ($type eq 'close') {
        $ok->($data);
      }
    })->then (sub {
      return $tcp->push_write (\$input);
    });
  });
  return $p;
} # rawclient

for my $status (
  200, 201, 204, 205, 207,
  300, 301, 302, 303, 304,
  400, 401, 402, 403, 404, 412,
  500, 501, 502, 503, 504, 505, 507, 507, 508,
  600, 601, 700,
) {
  test {
    my $c = shift;

    my $host = '127.0.0.1';
    my $port = find_listenable_port;
    my $close_server;
    my $server_name = rand;
    my $server_p = Promise->new (sub {
      my ($ok) = @_;
      my $server = tcp_server $host, $port, sub {
        my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {});
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
      return [$status, ['Hoge', 'foo', 'Fuga', $env->{HTTP_FUGA} || '',
                        'Request-URL', $env->{REQUEST_URI},
                        'Request-Via', $env->{HTTP_VIA} || '',
                        'Request-Method', $env->{REQUEST_METHOD},
                        'Request-Connection', $env->{HTTP_CONNECTION} || ''],
              ['200!']];
    }, sub {
      my ($origin, $close) = @_;
      my $url = Web::URL->parse_string (q</abc?d>, $origin);
      my $client = Web::Transport::BasicClient->new_from_url ($url, {
        proxy_manager => $pm,
      });
      promised_cleanup {
        $close_server->();
        return $client->close->then ($close);
      } $client->request (url => $url, headers => {'Fuga' => 'a b'})->then (sub {
        my $res = $_[0];
        test {
          is $res->status, $status;
          ok defined $res->status_text;
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
          if ($status == 204 or $status == 304) {
            is $res->header ('Transfer-Encoding'), undef;
            is $res->header ('Content-Length'), undef;
            is $res->body_bytes, '';
          } elsif ($status == 205) {
            is $res->header ('Transfer-Encoding'), 'chunked';
            is $res->header ('Content-Length'), undef;
            is $res->body_bytes, '';
          } else {
            is $res->header ('Transfer-Encoding'), undef;
            is $res->header ('Content-Length'), 4;
            is $res->body_bytes, '200!';
          }
          ok ! $res->incomplete;
        } $c;
      });
    }, server_name => $server_name);
  } n => 16, name => ['Basic request and response forwarding', $status];
} # $status

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {});
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
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
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
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {});
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
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
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
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {server_header => $server_name});
      promised_cleanup { $ok->() } $con->completed;
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } Promise->resolve->then (sub {
    my $rhost = rand . 'foo.bar.test';
    my $rport = 1024 + int rand 10000;
    promised_cleanup {
      $close_server->();
    } rawclient (Web::Host->parse_string ($host), $port,
                 "GET http://$rhost:$rport/a HTTP/1.0\x0D\x0AHost: $rhost:$rport\x0D\x0A\x0D\x0A")->then (sub {
      my $got = $_[0];
      test {
        like $got, qr{^HTTP/1.1 504 Gateway Timeout\x0D\x0A};
      } $c;
    });
  });
} n => 1, name => 'unresolvable host (504)';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_name = rand;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {server_header => $server_name});
      promised_cleanup { $ok->() } $con->completed;
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } Promise->resolve->then (sub {
    my $rhost = rand . 'foo.bar.test';
    my $rport = 1024 + int rand 10000;
    promised_cleanup {
      $close_server->();
    } rawclient (Web::Host->parse_string ($host), $port,
                 "GET ftp://$rhost:$rport/a HTTP/1.0\x0D\x0AHost: $rhost:$rport\x0D\x0A\x0D\x0A")->then (sub {
      my $got = $_[0];
      test {
        like $got, qr{^HTTP/1.1 504 Gateway Timeout\x0D\x0A};
      } $c;
    });
  });
} n => 1, name => 'bad URL scheme (504)';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_name = rand;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {server_header => $server_name});
      promised_cleanup { $ok->() } $con->completed;
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } Promise->resolve->then (sub {
    my $rhost = rand . 'foo.bar.test';
    my $rport = 1024 + int rand 10000;
    promised_cleanup {
      $close_server->();
    } rawclient (Web::Host->parse_string ($host), $port,
                 "GET https://$rhost:$rport/a HTTP/1.0\x0D\x0AHost: $rhost:$rport\x0D\x0A\x0D\x0A")->then (sub {
      my $got = $_[0];
      test {
        like $got, qr{^HTTP/1.1 504 Gateway Timeout\x0D\x0A};
      } $c;
    });
  });
} n => 1, name => 'bad URL scheme (504)';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_name = rand;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {server_header => $server_name});
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
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close;
    } $client->request (url => $url)->then (sub {
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
} n => 8, name => 'bad remote host (504)';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_name = rand;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {server_header => $server_name, client => {
        last_resort_timeout => 3,
      }});
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
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
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
} n => 8, name => 'remote host timeout (504)';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_name = rand;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {server_header => $server_name});
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
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
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
} n => 7, name => 'remote bad response (502)';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_name = rand;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {server_header => $server_name});
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
    "HTTP/1.1 200 ok"CRLF
    "content-length: 100"CRLF
    "server: abcde"CRLF
    "date: xyzab"CRLF
    reset
  })->then (sub {
    my $server = $_[0];
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}/});
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close;
    } $client->request (url => $url, headers => {'Fuga' => 'a b'})->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 504;
        is $res->status_text, 'Gateway Timeout';
        is $res->header ('Server'), $server_name;
        like $res->header ('Date'), qr/^\w+, \d\d \w+ \d+ \d\d:\d\d:\d\d GMT$/;
        is $res->header ('Connection'), undef;
        is $res->header ('Transfer-Encoding'), 'chunked';
        is $res->body_bytes, '504';
        ok ! $res->incomplete;
      } $c;
    });
  });
} n => 8, name => 'remote truncated response (reset)';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {});
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
    "HTTP/1.0 200 ok"CRLF
    "content-length: 100"CRLF
    "server: abcde"CRLF
    "date: xyzab"CRLF
    CRLF
    "abcdefg"
    close
  })->then (sub {
    my $server = $_[0];
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}/});
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close;
    } $client->request (url => $url, headers => {'Fuga' => 'a b'}, stream => 1)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 200;
        is $res->status_text, 'ok';
        is $res->header ('Server'), "abcde";
        is $res->header ('Date'), "xyzab";
        is $res->header ('Connection'), undef;
        is $res->header ('Transfer-Encoding'), undef;
        is $res->header ('Content-Length'), 100;
      } $c;
      my $reader = $res->body_stream->get_reader ('byob');
      my $value = '';
      my $read; $read = sub {
        return $reader->read (DataView->new (ArrayBuffer->new (3)))->then (sub {
          return if $_[0]->{done};
          $value .= $_[0]->{value}->manakai_to_string;
          return $read->();
        });
      };
      return ((promised_cleanup { undef $read } $read->())->then (sub {
        test {
          is $value, 'abcdefg';
          ok $res->incomplete;
        } $c;
      }));
    });
  });
} n => 9, name => 'remote truncated response 2';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {});
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
    "HTTP/1.1 200 ok"CRLF
    "content-length: 100"CRLF
    "server: abcde"CRLF
    "date: xyzab"CRLF
    CRLF
    "abcdefg"
    close
  })->then (sub {
    my $server = $_[0];
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}/});
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close;
    } $client->request (url => $url, headers => {'Fuga' => 'a b'}, stream => 1)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 200;
        is $res->status_text, 'ok';
        is $res->header ('Server'), "abcde";
        is $res->header ('Date'), "xyzab";
        is $res->header ('Connection'), undef;
        is $res->header ('Transfer-Encoding'), undef;
        is $res->header ('Content-Length'), 100;
      } $c;
      my $reader = $res->body_stream->get_reader ('byob');
      my $value = '';
      my $read; $read = sub {
        return $reader->read (DataView->new (ArrayBuffer->new (3)))->then (sub {
          return if $_[0]->{done};
          $value .= $_[0]->{value}->manakai_to_string;
          return $read->();
        });
      };
      return ((promised_cleanup { undef $read } $read->())->then (sub {
        test {
          is $value, 'abcdefg';
          ok $res->incomplete;
        } $c;
      }));
    });
  });
} n => 9, name => 'remote truncated response 1';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {});
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
    return [201, [], ['200!']];
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url, method => 'HEAD')->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 201;
        is $res->status_text, 'Created';
        is $res->body_bytes, '';
        ok ! $res->incomplete;
      } $c;
    });
  });
} n => 4, name => 'HEAD request';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {});
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
    return [201, ['Content-Length', '1200'], ['200!']];
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url, method => 'HEAD')->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 201;
        is $res->status_text, 'Created';
        is $res->body_bytes, '';
        ok ! $res->incomplete;
      } $c;
    });
  });
} n => 4, name => 'HEAD request (response with Content-Length: header)';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {});
      promised_cleanup { $ok->() } $con->completed;
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $got = '';
  promised_cleanup {
    done $c; undef $c;
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    read $env->{'psgi.input'}, $got, $env->{CONTENT_LENGTH};
    return [201, [], ['200!']];
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    my $data = 'abcdefgh';
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url, body => $data)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 201;
        is $res->status_text, 'Created';
        is $got, $data, 'server-received request body';
      } $c;
    });
  });
} n => 3, name => 'request body forwarding';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {});
      promised_cleanup { $ok->() } $con->completed;
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $got = '';
  promised_cleanup {
    done $c; undef $c;
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    read $env->{'psgi.input'}, $got, $env->{CONTENT_LENGTH};
    return [201, [], ['200!']];
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    my $data = 'abcdefgh' x 1000 x 100;
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url, body => $data)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 201;
        is $res->status_text, 'Created';
        is $got, $data, 'server-received request body';
      } $c;
    });
  });
} n => 3, name => 'request body forwarding (large body)';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {});
      promised_cleanup { $ok->() } $con->completed;
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $data = 'abcdefgh' x 1000;
  promised_cleanup {
    done $c; undef $c;
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    return [201, [], [$data]];
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 201;
        is $res->status_text, 'Created';
        is $res->body_bytes, $data, 'client-received response body';
      } $c;
    });
  });
} n => 3, name => 'response body forwarding';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {});
      promised_cleanup { $ok->() } $con->completed;
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $data = 'abcdefgh' x 1000 x 1000;
  promised_cleanup {
    done $c; undef $c;
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    return [201, [], [$data]];
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 201;
        is $res->status_text, 'Created';
        is $res->body_bytes, $data, 'client-received response body';
      } $c;
    });
  });
} n => 3, name => 'response body forwarding (large data)';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {});
      promised_cleanup { $ok->() } $con->completed;
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $responder;
  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    return sub { $responder = $_[0] };
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    my $req = $client->request (url => $url);
    (promised_wait_until { defined $responder })->then (sub {
      return $client->abort;
    });
    promised_cleanup {
      $close_server->();
      undef $responder;
      return $client->close->then ($close);
    } $req->catch (sub {
      my $result = $_[0];
      test {
        ok $result->is_network_error, $result;
        is $result->network_error_message, 'Client aborted';
      } $c;
    });
  });
} n => 2, name => 'client abort before response received';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {});
      promised_cleanup { $ok->() } $con->completed;
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $origin;
  my $value = rand;
  my $value2 = rand;
  my $value3 = rand;
  my $value4 = rand;
  promised_cleanup {
    done $c; undef $c;
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    test {
      is $env->{HTTP_HOST}, $origin->hostport;
      is $env->{HTTP_FOO}, $value;
      is $env->{HTTP_ACCEPT}, $value2;
      is $env->{HTTP_ACCEPT_LANGUAGE}, $value3;
      is $env->{HTTP_USER_AGENT}, $value4;
      is $env->{HTTP_VIA}, undef;
      is $env->{HTTP_WARNING}, undef;
    } $c;
    return [201, [], ['200!']];
  }, sub {
    my $close;
    ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url, headers => {
      Foo => $value, Accept => $value2, 'Accept-Language' => $value3,
      'User-Agent' => $value4,
    });
  });
} n => 7, name => 'request headers forwarding';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {});
      promised_cleanup { $ok->() } $con->completed;
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $origin;
  my $value = rand;
  my $value2 = rand;
  my $value3 = rand;
  my $value4 = rand;
  promised_cleanup {
    done $c; undef $c;
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    test {
      is $env->{HTTP_HOST}, $origin->hostport;
      is $env->{HTTP_FOO}, undef;
      is $env->{HTTP_ACCEPT}, undef;
      is $env->{HTTP_ACCEPT_LANGUAGE}, undef;
      is $env->{HTTP_USER_AGENT}, undef;
      is $env->{HTTP_VIA}, undef;
      is $env->{HTTP_WARNING}, undef;
      is $env->{HTTP_CONNECTION}, 'keep-alive';
    } $c;
    return [201, [], ['200!']];
  }, sub {
    my $close;
    ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url, headers => {
      Foo => $value, Accept => $value2, 'Accept-Language' => $value3,
      'User-Agent' => $value4,
      Connection => ['foo, Bar,Connection,Host', 'User-Agent', 'Accept , Accept-Language'],
    });
  });
} n => 8, name => 'request headers forwarding, Connection:';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {});
      promised_cleanup { $ok->() } $con->completed;
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $origin;
  my $value = rand;
  promised_cleanup {
    done $c; undef $c;
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    test {
      is $env->{HTTP_COOKIE}, $value;
      is $env->{HTTP_PRAGMA}, 'no-cache', 'Added by client requestconstructor';
      is $env->{HTTP_CACHE_CONTROL}, 'no-store', 'Added by client requestconstructor';
    } $c;
    return [201, [], ['200!']];
  }, sub {
    my $close;
    ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url, headers => {
      cookie => $value,
    });
  });
} n => 3, name => 'request headers forwarding, cookies';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {});
      promised_cleanup { $ok->() } $con->completed;
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $origin;
  my $value = rand;
  promised_cleanup {
    done $c; undef $c;
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    test {
      is $env->{HTTP_COOKIE}, $value;
      is $env->{HTTP_PRAGMA}, 'no-cache', 'Added by client requestconstructor';
      is $env->{HTTP_CACHE_CONTROL}, 'must-revalidate, no-store', 'Added by client requestconstructor';
    } $c;
    return [201, [], ['200!']];
  }, sub {
    my $close;
    ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url, headers => {
      cookie => $value,
      'Cache-control' => 'must-revalidate',
    });
  });
} n => 3, name => 'request headers forwarding, cookies, cache-control';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {});
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
    return [201, ['Hoge', rand, 'Connection', 'Hoge'], ['200!']];
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url)->then (sub {
      my $result = $_[0];
      test {
        is $result->header ('Connection'), undef;
        is $result->header ('Hoge'), undef;
      } $c;
    });
  });
} n => 2, name => 'response headers forwarding, Connection:';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {});
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
    return [201, ['Hoge', rand, 'Connection', 'Server,date'], ['200!']];
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url)->then (sub {
      my $result = $_[0];
      test {
        is $result->header ('Connection'), undef;
        is $result->header ('Server'), undef;
        like $result->header ('Date'), qr/^\w+, \d\d \w+ \d+ \d\d:\d\d:\d\d GMT$/;
      } $c;
    });
  });
} n => 3, name => 'response headers forwarding, Connection: Server,Date';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {});
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
    "abcdefg"
    close
  })->then (sub {
    my $server = $_[0];
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}/});
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close;
    } $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 200;
        is $res->status_text, 'OK';
        is $res->header ('Server'), undef;
        like $res->header ('Date'), qr/^\w+, \d\d \w+ \d+ \d\d:\d\d:\d\d GMT$/;
        is $res->header ('Connection'), undef;
        is $res->header ('Content-Type'), undef;
        is $res->header ('Transfer-Encoding'), 'chunked';
        is $res->body_bytes, 'abcdefg';
        ok ! $res->incomplete;
      } $c;
    });
  });
} n => 9, name => 'remote HTTP/0.9 response';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {});
      promised_cleanup { $ok->() } $con->completed;
    };
    $close_server = sub { undef $server };
  });

  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    return [201, ['Hoge', rand], ['200!']];
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string ("/abc", $origin);
    promised_cleanup {
      $close_server->();
      return $close->();
    } rawclient (Web::Host->parse_string ($host), $port, "GET @{[$url->stringify]}\x0D\x0A")->then (sub {
      my $got = $_[0];
      test {
        is $got, "200!";
      } $c;
    });
  });
} n => 1, name => 'HTTP/0.9 client request';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {});
      promised_cleanup { $ok->() } $con->completed;
    };
    $close_server = sub { undef $server };
  });

  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    return [201, ['Hoge', rand], ['200!']];
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string ("/abc", $origin);
    promised_cleanup {
      $close_server->();
      return $close->();
    } rawclient (Web::Host->parse_string ($host), $port, "GET @{[$url->stringify]} HTTP/1.0\x0D\x0A\x0D\x0A")->then (sub {
      my $got = $_[0];
      test {
        like $got, qr{^HTTP/1.1 201 Created\x0D\x0A};
        like $got, qr{\x0D\x0A200!\z};
      } $c;
    });
  });
} n => 2, name => 'HTTP/1.0 client request';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {});
      promised_cleanup { $ok->() } $con->completed;
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    return [407, [], ['200!']];
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url)->then (sub {
      my $result = $_[0];
      test {
        is $result->status, 504;
      } $c;
    });
  });
} n => 1, name => 'server 407 response (proxy does not have an upstream proxy)';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {});
      promised_cleanup { $ok->() } $con->completed;
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $host2 = '127.0.0.1';
  my $port2 = find_listenable_port;
  my $close_server2;
  my $server_p2 = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host2, $port2, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {client => {proxy_manager => $pm}});
      promised_cleanup { $ok->() } $con->completed;
    };
    $close_server2 = sub { undef $server };
  });

  my $pm2 = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host2, port => $port2}]);

  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p2;
  } promised_cleanup {
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    return [207, [], ['200!']];
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm2,
    });
    promised_cleanup {
      $close_server->();
      $close_server2->();
      return $client->close->then ($close);
    } $client->request (url => $url)->then (sub {
      my $result = $_[0];
      test {
        is $result->status, 207;
        is $result->body_bytes, '200!';
      } $c;
    });
  });
} n => 2, name => 'proxy has an upstream proxy';

test {
  my $c = shift;

  rawserver (q{
    receive "GET"
    "HTTP/1.1 407 ok"CRLF
    "content-length: 100"CRLF
    "server: abcde"CRLF
    "date: xyzab"CRLF
    CRLF
    "abcdefg"
  })->then (sub {
    my $server = $_[0];
    my $pm2 = Web::Transport::ConstProxyManager->new_from_arrayref
        ([{protocol => 'http',
           host => $server->{host}, port => $server->{port}}]);

    my $host = '127.0.0.1';
    my $port = find_listenable_port;
    my $close_server;
    my $server_name = rand;
    my $server_p = Promise->new (sub {
      my ($ok) = @_;
      my $server = tcp_server $host, $port, sub {
        my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {client => {proxy_manager => $pm2}, server_header => $server_name});
        promised_cleanup { $ok->() } $con->completed;
      };
      $close_server = sub { undef $server };
    });
    my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
        ([{protocol => 'http', host => $host, port => $port}]);

    my $url = Web::URL->parse_string (qq{http://hoge.test/});
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      done $c; undef $c;
    } promised_cleanup {
      return $server_p;
    } promised_cleanup {
      $close_server->();
      return $client->close;
    } $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 504;
        is $res->status_text, 'Gateway Timeout';
        is $res->header ('Server'), $server_name;
        like $res->header ('Date'), qr/^\w+, \d\d \w+ \d+ \d\d:\d\d:\d\d GMT$/;
        is $res->header ('Connection'), undef;
        is $res->header ('Transfer-Encoding'), 'chunked';
        is $res->body_bytes, '504';
        ok ! $res->incomplete;
      } $c;
    });
  });
} n => 8, name => 'remote 407 response';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $cert_args = {host => 'tlstestproxy.test'};
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {tls => {
        ca_file => Test::Certificates->ca_path ('cert.pem'),
        cert_file => Test::Certificates->cert_path ('cert-chained.pem', $cert_args),
        key_file => Test::Certificates->cert_path ('key.pem', $cert_args),
      }});
      promised_cleanup { $ok->() } $con->completed;
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'https', host => $cert_args->{host}, port => $port,
         tls_options => {ca_file => Test::Certificates->ca_path ('cert.pem')}}]);

  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    return [201, [Foo => 'bar'], ['200!']];
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
      resolver => TLSTestResolver->new ($host),
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url)->then (sub {
      my $result = $_[0];
      test {
        is $result->status, 201;
        is $result->header ('Foo'), 'bar';
        is $result->body_bytes, '200!';
      } $c;
    });
  });
} n => 3, name => 'TLS proxy server';

test {
  my $c = shift;

  my $path = path (__FILE__)->parent->parent->child ('local/' . rand . '.sock')->absolute;
  my $close_server;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server 'unix/', $path, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {});
      promised_cleanup { $ok->() } $con->completed;
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'unix', path => $path}]);

  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    return [201, [Foo => 'bar'], ['200!']];
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url)->then (sub {
      my $result = $_[0];
      test {
        is $result->status, 201;
        is $result->header ('Foo'), 'bar';
        is $result->body_bytes, '200!';
      } $c;
    });
  });
} n => 3, name => 'Unix proxy server';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my @con;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {});
      promised_cleanup { $ok->() } $con->completed;
      push @con, $con;
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $server_invoked = 0;
  my @end;
  promised_cleanup {
    @end = ();
    done $c; undef $c;
  } promised_cleanup {
    @con = ();
    return Promise->all (\@end);
  } promised_cleanup {
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    $server_invoked++;
    return [201, [], ['200!']];
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 201;
        is $res->status_text, 'Created';
      } $c;
      push @end, $con[0]->close_after_current_response;
      return $client->request (url => $url);
    })->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 201;
        is $res->status_text, 'Created';
        is $server_invoked, 2;
      } $c;
    });
  });
} n => 5, name => 'close_after_current_response 1';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my @con;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {});
      promised_cleanup { $ok->() } $con->completed;
      push @con, $con;
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $server_invoked = 0;
  my @end;
  promised_cleanup {
    @end = ();
    done $c; undef $c;
  } promised_cleanup {
    @con = ();
    return Promise->all (\@end);
  } promised_cleanup {
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    $server_invoked++;
    return [201, [], ['200!']];
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    my $req = $client->request (url => $url);
    (promised_wait_until { $server_invoked } interval => 0.1)->then (sub {
      push @end, $con[0]->close_after_current_response;
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $req->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 201;
        is $res->status_text, 'Created';
        is $server_invoked, 1;
      } $c;
    });
  });
} n => 3, name => 'close_after_current_response 2';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {});
      promised_cleanup { $ok->() } $con->completed;
    };
    $close_server = sub { undef $server };
  });

  my $url = Web::URL->parse_string (qq<http://$host:$port/abc?d>);
  my $client = Web::Transport::BasicClient->new_from_url ($url);
  promised_cleanup {
    $close_server->();
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } $client->request (url => $url)->then (sub {
    my $result = $_[0];
    test {
      is $result->status, 504;
      is $result->status_text, 'Gateway Timeout';
      is $result->body_bytes, 504;
    } $c;
  });
} n => 3, name => 'default pre-handler - loop detection (http)';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $cert_args = {host => 'tlstestserver.test'};
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {tls => {
        ca_file => Test::Certificates->ca_path ('cert.pem'),
        cert_file => Test::Certificates->cert_path ('cert-chained.pem', $cert_args),
        key_file => Test::Certificates->cert_path ('key.pem', $cert_args),
      }});
      promised_cleanup { $ok->() } $con->completed;
    };
    $close_server = sub { undef $server };
  }); # $server_p

  my $url = Web::URL->parse_string (qq<https://tlstestserver.test:$port/abc?d>);
  my $client = Web::Transport::BasicClient->new_from_url ($url, {
    resolver => TLSTestResolver->new ($host),
    tls_options => {
      ca_file => Test::Certificates->ca_path ('cert.pem'),
    },
  });
  promised_cleanup {
    $close_server->();
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } $client->request (url => $url)->then (sub {
    my $result = $_[0];
    test {
      is $result->status, 504;
      is $result->status_text, 'Gateway Timeout';
      is $result->body_bytes, 504;
    } $c;
  });
} n => 3, name => 'default pre-handler - loop detection (https)';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_name = rand;
  my $exception_invoked = 0;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {server_header => $server_name});
      promised_cleanup { $ok->() } $con->completed;
      $con->onexception (sub {
        my ($s, $x) = @_;
        test {
          is $s, $con;
          is $x->name, 'Protocol error', $x;
          is $x->message, 'HTTP |TRACE| method';
          is $x->file_name, __FILE__;
          is $x->line_number, __LINE__-9;
        } $c;
        $exception_invoked++;
        undef $con;
      });
    };
    $close_server = sub { undef $server };
  });

  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $server_invoked = 0;
  promised_cleanup {
    done $c; undef $c;
    return $server_p;
  } psgi_server (sub ($) {
    my $env = $_[0];
    $server_invoked++;
    return [201, [], ['200!']];
  }, sub {
    my ($origin, $close) = @_;
    my $url = Web::URL->parse_string (q</abc?d>, $origin);
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      $close_server->();
      return $client->close->then ($close);
    } $client->request (url => $url, method => 'TRACE')->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 405;
        is $res->status_text, 'Method Not Allowed';
        is $res->header ('Server'), $server_name;
        like $res->header ('Date'), qr/^\w+, \d\d \w+ \d+ \d\d:\d\d:\d\d GMT$/;
        is $res->body_bytes, "405";
        ok ! $res->incomplete;
        is $server_invoked, 0;
        is $exception_invoked, 1;
      } $c;
    });
  });
} n => 13, name => 'TRACE';

test {
  my $c = shift;
  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_name = undef;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {client => {}, server_header => $server_name});
      promised_cleanup { $ok->() } $con->completed;
    };
    $close_server = sub { undef $server };
  });
  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $url = Web::URL->parse_string (qq{http://hoge.test/});
  my $client = Web::Transport::BasicClient->new_from_url ($url, {
    proxy_manager => $pm,
  });
  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } promised_cleanup {
    $close_server->();
    return $client->close;
  } $client->request (url => $url)->then (sub {
    my $res = $_[0];
    test {
      is $res->status, 504;
      is $res->header ('Server'), 'httpd';
      like $res->header ('Date'), qr/^\w+, \d\d \w+ \d+ \d\d:\d\d:\d\d GMT$/;
    } $c;
  });
} n => 3, name => 'server_header default';

for my $value ('', '0', 'abc/1.2', 'hoge fuga') {
  test {
    my $c = shift;
    my $host = '127.0.0.1';
    my $port = find_listenable_port;
    my $close_server;
    my $server_p = Promise->new (sub {
      my ($ok) = @_;
      my $server = tcp_server $host, $port, sub {
        my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {client => {}, server_header => $value});
        promised_cleanup { $ok->() } $con->completed;
      };
      $close_server = sub { undef $server };
    });
    my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
        ([{protocol => 'http', host => $host, port => $port}]);

    my $url = Web::URL->parse_string (qq{http://hoge.test/});
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      proxy_manager => $pm,
    });
    promised_cleanup {
      done $c; undef $c;
    } promised_cleanup {
      return $server_p;
    } promised_cleanup {
      $close_server->();
      return $client->close;
    } $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 504;
        is $res->header ('Server'), $value;
        like $res->header ('Date'), qr/^\w+, \d\d \w+ \d+ \d\d:\d\d:\d\d GMT$/;
      } $c;
    });
  } n => 3, name => ['server_header', $value];
} # $value

test {
  my $c = shift;
  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {client => {}, server_header => "a\x{5000}"});
      promised_cleanup { $ok->() } $con->completed;
    };
    $close_server = sub { undef $server };
  });
  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $url = Web::URL->parse_string (qq{http://hoge.test/});
  my $client = Web::Transport::BasicClient->new_from_url ($url, {
    proxy_manager => $pm,
  });
  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } promised_cleanup {
    $close_server->();
    return $client->close;
  } $client->request (url => $url)->then (sub {
    my $res = $_[0];
    test {
      is $res->status, 504;
      is $res->header ('Server'), "a\xE5\x80\x80";
      like $res->header ('Date'), qr/^\w+, \d\d \w+ \d+ \d\d:\d\d:\d\d GMT$/;
    } $c;
  });
} n => 3, name => 'server_header utf-8';

test {
  my $c = shift;
  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $exception_invoked = 0;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {client => {}, server_header => "a\x0Db"});
      promised_cleanup { $ok->() } $con->completed;
      $con->onexception (sub {
        my ($s, $x) = @_;
        $exception_invoked++;
        if ($exception_invoked == 2) {
          test {
            is $s, $con;
            is $x->name, 'TypeError', $x;
            is $x->message, 'Bad header value |Server: a\x0Db|';
            is $x->file_name, __FILE__;
            is $x->line_number, __LINE__-11;
          } $c;
          undef $con;
        }
      });
    };
    $close_server = sub { undef $server };
  });
  my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
      ([{protocol => 'http', host => $host, port => $port}]);

  my $url = Web::URL->parse_string (qq{http://hoge.test/});
  my $client = Web::Transport::BasicClient->new_from_url ($url, {
    proxy_manager => $pm,
  });
  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } promised_cleanup {
    $close_server->();
    return $client->close;
  } $client->request (url => $url)->catch (sub {
    my $res = $_[0];
    test {
      ok $res->is_network_error, $res;
      is $res->network_error_message, 'Connection closed without response';
      is $exception_invoked, 2; # can't resolve host.test; bad header value
    } $c;
  });
} n => 8, name => 'server_header bad value';

Test::Certificates->wait_create_cert ({host => 'tlstestproxy.test'});
Test::Certificates->wait_create_cert ({host => 'tlstestserver.test'});
run_tests;

=head1 LICENSE

Copyright 2016-2017 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
