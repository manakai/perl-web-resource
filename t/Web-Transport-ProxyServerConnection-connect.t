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
use ArrayBuffer;
use DataView;
use ReadableStream;
use Web::URL;
use Web::Transport::BasicClient;
use Web::Transport::ConstProxyManager;
use Web::Transport::ProxyServerConnection;
use Web::Transport::PSGIServerConnection;
use Web::Transport::TCPTransport;
use Web::Transport::PKI::Generator;
use Web::Transport::FindPort;

sub ca_cert () {
  my $gen = Web::Transport::PKI::Generator->new;
  return $gen->create_rsa_key->then (sub {
    my $ca_rsa = $_[0];
    my $name = rand;
    return $gen->create_certificate (
      rsa => $ca_rsa,
      ca_rsa => $ca_rsa,
      subject => {O => 'The Root CA' . $name},
      issuer => {O => 'The Root CA' . $name},
      not_before => time - 60,
      not_after => time + 3600,
      serial_number => 1,
      ca => 1,
    )->then (sub {
      my $ca_cert = $_[0];
      return [$ca_cert, $ca_rsa];
    });
  });
} # ca_cert

sub ee_cert ($$) {
  my ($ca_cert, $ca_rsa) = @{$_[0]};
  my $host = $_[1];
  my $gen = Web::Transport::PKI::Generator->new;
  return $gen->create_rsa_key->then (sub {
    my $rsa = $_[0];
    return $gen->create_certificate (
      rsa => $rsa,
      ca_rsa => $ca_rsa,
      ca_cert => $ca_cert,
      not_before => time - 30,
      not_after => time + 3000,
      serial_number => 2,
      subject => {CN => 'server.test'},
      san_hosts => [$host],
      ee => 1,
    )->then (sub {
      my $cert = $_[0];
      return [$cert, $rsa];
    });
  });
} # ee_cert

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

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_name = rand;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
      });
      promised_cleanup { $ok->() } $con->completed;
    };
    $close_server = sub { undef $server };
  });

  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } promised_cleanup {
    $close_server->();
  } rawclient (Web::Host->parse_string ($host), $port, "CONNECT abc:24 HTTP/1.1\x0D\x0AHost: abc:24\x0D\x0A\x0D\x0A")->then (sub {
    my $got = $_[0];
    test {
      like $got, qr{^HTTP/1.1 405 Method Not Allowed\x0D\x0A};
      like $got, qr{\x0D\x0AConnection: close\x0D\x0A};
      like $got, qr{\x0D\x0A\x0D\x0A3\x0D\x0A405\x0D\x0A0\x0D\x0A\x0D\x0A\z};
    } $c;
  });
} n => 3, name => ['default error response'];

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_name = rand;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
      });
      promised_cleanup { $ok->() } $con->completed;
    };
    $close_server = sub { undef $server };
  });

  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } promised_cleanup {
    $close_server->();
  } rawclient (Web::Host->parse_string ($host), $port, "CONNECT abc:24 HTTP/1.0\x0D\x0AHost: abc:24\x0D\x0A\x0D\x0A")->then (sub {
    my $got = $_[0];
    test {
      like $got, qr{^HTTP/1.1 405 Method Not Allowed\x0D\x0A};
      like $got, qr{\x0D\x0AConnection: close\x0D\x0A};
      like $got, qr{\x0D\x0A\x0D\x0A405\z};
    } $c;
  });
} n => 3, name => ['default error response (HTTP/1.0)'];

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_name = rand;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
        handle_request => sub {
          my $args = $_[0];
          return {response => {
            status => 567,
            status_text => "abc",
            headers => [["Foo-" => "ab c"]],
            body => "aa bb cc",
          }};
        },
      });
      promised_cleanup { $ok->() } $con->completed;
    };
    $close_server = sub { undef $server };
  });

  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } promised_cleanup {
    $close_server->();
  } rawclient (Web::Host->parse_string ($host), $port, "CONNECT abc:24 HTTP/1.1\x0D\x0AHost: abc:24\x0D\x0A\x0D\x0A")->then (sub {
    my $got = $_[0];
    test {
      like $got, qr{^HTTP/1.1 567 abc\x0D\x0A};
      like $got, qr{\x0D\x0AFoo-: ab c\x0D\x0A};
      like $got, qr{\x0D\x0A\x0D\x0A8\x0D\x0Aaa bb cc\x0D\x0A0\x0D\x0A\x0D\x0A\z};
    } $c;
  });
} n => 3, name => ['handle_request error response'];

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_name = rand;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
        handle_request => sub {
          my $args = $_[0];
          return {response => {
            status => 208,
            status_text => "abc",
            headers => [["Foo-" => "ab c"]],
            body => "aa bb cc",
          }};
        },
      });
      promised_cleanup { $ok->() } $con->completed;
    };
    $close_server = sub { undef $server };
  });

  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } promised_cleanup {
    $close_server->();
  } rawclient (Web::Host->parse_string ($host), $port, "CONNECT abc:24 HTTP/1.1\x0D\x0AHost: abc:24\x0D\x0A\x0D\x0A")->then (sub {
    my $got = $_[0];
    test {
      like $got, qr{^HTTP/1.1 208 abc\x0D\x0A};
      like $got, qr{\x0D\x0AFoo-: ab c\x0D\x0A};
      like $got, qr{\x0D\x0A\x0D\x0Aaa bb cc\z};
    } $c;
  });
} n => 3, name => ['handle_request 2xx response (body)'];

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_name = rand;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
        handle_request => sub {
          my $args = $_[0];
          my $rs = new ReadableStream ({
            type => 'bytes',
            start => sub {
              my $rc = $_[1];
              $rc->enqueue (DataView->new (ArrayBuffer->new_from_scalarref (\"aa b")));
              promised_sleep (1)->then (sub {
                $rc->enqueue (DataView->new (ArrayBuffer->new_from_scalarref (\"b cc")));
                $rc->close;
              });
            },
          });

          return {response => {
            status => 208,
            status_text => "abc",
            headers => [["Foo-" => "ab c"]],
            body_stream => $rs,
          }};
        },
      });
      promised_cleanup { $ok->() } $con->completed;
    };
    $close_server = sub { undef $server };
  });

  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } promised_cleanup {
    $close_server->();
  } rawclient (Web::Host->parse_string ($host), $port, "CONNECT abc:24 HTTP/1.1\x0D\x0AHost: abc:24\x0D\x0A\x0D\x0A")->then (sub {
    my $got = $_[0];
    test {
      like $got, qr{^HTTP/1.1 208 abc\x0D\x0A};
      like $got, qr{\x0D\x0AFoo-: ab c\x0D\x0A};
      like $got, qr{\x0D\x0A\x0D\x0Aaa bb cc\z};
    } $c;
  });
} n => 3, name => ['handle_request 2xx response (body)'];

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_name = rand;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
        server_header => $server_name,
        handle_request => sub {
          my $args = $_[0];
          $args->{request}->{method} = 'CONNECT';
          return $args;
        },
      });
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
    "server: foo"CRLF
    CRLF
    "efg"
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
        is $res->status, 405;
        is $res->status_text, 'Method Not Allowed';
        is $res->header ('server'), $server_name;
        is $res->header ('Connection'), 'close';
        is $res->body_bytes, '405';
      } $c;
    });
  });
} n => 5, name => 'handle_request rewrites non-CONNECT request method to CONNECT';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_name = rand;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
        server_header => $server_name,
        handle_request => sub {
          my $args = $_[0];
          $args->{request}->{method} = 'GET';
          return $args;
        },
      });
      promised_cleanup { $ok->() } $con->completed;
    };
    $close_server = sub { undef $server };
  });

  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } rawserver (q{
    receive "GET"
    "HTTP/1.1 345 ok"CRLF
    "server: foo"CRLF
    CRLF
    "efg"
    close
  })->then (sub {
    my $server = $_[0];
    promised_cleanup {
      $close_server->();
    } rawclient (Web::Host->parse_string ($host), $port, "CONNECT $server->{host}:$server->{port} HTTP/1.1\x0D\x0AHost: $server->{host}:$server->{port}\x0D\x0A\x0D\x0A")->then (sub {
      my $got = $_[0];
      test {
        like $got, qr{^HTTP/1.1 345 ok\x0D\x0A};
        like $got, qr{\x0D\x0Aserver: foo\x0D\x0A};
        like $got, qr{\x0D\x0A\x0D\x0A3\x0D\x0Aefg\x0D\x0A0\x0D\x0A\x0D\x0A\z};
      } $c;
    });
  });
} n => 3, name => 'handle_request rewrites CONNECT request method to non-CONNECT, non-2xx response';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $close_server;
  my $server_name = rand;
  my $server_p = Promise->new (sub {
    my ($ok) = @_;
    my $server = tcp_server $host, $port, sub {
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
        server_header => $server_name,
        handle_request => sub {
          my $args = $_[0];
          $args->{request}->{method} = 'GET';
          return $args;
        },
      });
      promised_cleanup { $ok->() } $con->completed;
    };
    $close_server = sub { undef $server };
  });

  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } rawserver (q{
    receive "GET"
    "HTTP/1.1 245 ok"CRLF
    "server: foo"CRLF
    CRLF
    "efg"
    sleep 1
    "AVC"
    close
  })->then (sub {
    my $server = $_[0];
    promised_cleanup {
      $close_server->();
    } rawclient (Web::Host->parse_string ($host), $port, "CONNECT $server->{host}:$server->{port} HTTP/1.1\x0D\x0AHost: $server->{host}:$server->{port}\x0D\x0A\x0D\x0A")->then (sub {
      my $got = $_[0];
      test {
        like $got, qr{^HTTP/1.1 245 ok\x0D\x0A};
        like $got, qr{\x0D\x0Aserver: foo\x0D\x0A};
        like $got, qr{\x0D\x0A\x0D\x0AefgAVC\z};
      } $c;
    });
  });
} n => 3, name => 'handle_request rewrites CONNECT request method to non-CONNECT, 2xx response';

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
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
        server_header => $server_name,
        handle_request => sub {
          die Web::Transport::ProtocolError->new ("ABC");
        },
      });
      $con->onexception (sub {
        my ($s, $x) = @_;
        test {
          is $s, $con;
          is $x->name, 'Protocol error', $x;
          is $x->message, "ABC";
          is $x->file_name, __FILE__;
          is $x->line_number, __LINE__-10;
        } $c;
        $exception_invoked++;
        undef $con;
      });
      promised_cleanup { $ok->() } $con->completed;
    };
    $close_server = sub { undef $server };
  });

  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } promised_cleanup {
    $close_server->();
  } rawclient (Web::Host->parse_string ($host), $port, "CONNECT foo.test:4323 HTTP/1.1\x0D\x0AHost: foo.test:4323\x0D\x0A\x0D\x0A")->then (sub {
    my $got = $_[0];
    test {
      like $got, qr{^HTTP/1.1 504 Gateway Timeout\x0D\x0A};
      like $got, qr{\x0D\x0AServer: $server_name\x0D\x0A};
      like $got, qr{\x0D\x0A\x0D\x0A3\x0D\x0A504\x0D\x0A0\x0D\x0A\x0D\x0A\z};
    } $c;
  });
} n => 8, name => 'handle_request rejected';

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
      my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
        server_header => $server_name,
        handle_request => sub {
          return {error => Web::Transport::ProtocolError->new ("ABC")};
        },
      });
      $con->onexception (sub {
        my ($s, $x) = @_;
        test {
          is $s, $con;
          is $x->name, 'Protocol error', $x;
          is $x->message, "ABC";
          is $x->file_name, __FILE__;
          is $x->line_number, __LINE__-10;
        } $c;
        $exception_invoked++;
        undef $con;
      });
      promised_cleanup { $ok->() } $con->completed;
    };
    $close_server = sub { undef $server };
  });

  promised_cleanup {
    done $c; undef $c;
  } promised_cleanup {
    return $server_p;
  } promised_cleanup {
    $close_server->();
  } rawclient (Web::Host->parse_string ($host), $port, "CONNECT foo.test:4323 HTTP/1.1\x0D\x0AHost: foo.test:4323\x0D\x0A\x0D\x0A")->then (sub {
    my $got = $_[0];
    test {
      like $got, qr{^HTTP/1.1 504 Gateway Timeout\x0D\x0A};
      like $got, qr{\x0D\x0AServer: $server_name\x0D\x0A};
      like $got, qr{\x0D\x0A\x0D\x0A3\x0D\x0A504\x0D\x0A0\x0D\x0A\x0D\x0A\z};
    } $c;
  });
} n => 8, name => 'handle_request returns error';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;

  my $remote_host = Web::Host->parse_string (rand . '.test');
  my $remote_port = 3533;
  ca_cert->then (sub {
    my ($ca_cert, $ca_rsa) = @{$_[0]};
    return ee_cert ($_[0], $remote_host)->then (sub {
      my ($ee_cert, $ee_rsa) = @{$_[0]};
      my $close_server;
      my $server_name = rand;
      my $server_p = Promise->new (sub {
        my ($ok) = @_;
        my $server = tcp_server $host, $port, sub {
          my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
            server_header => $server_name,
            handle_request => sub {
              my $args = $_[0];
              if ($args->{request}->{method} eq 'CONNECT') {
                $args->{upstream}->{type} = 'mitm';
                $args->{upstream}->{tls} = {
                  ca_cert => $ca_cert->to_pem,
                  cert => $ee_cert->to_pem,
                  key => $ee_rsa->to_pem,
                };
                return $args;
              }

              return {response => {
                status => 208,
                status_text => "abc",
                headers => [
                  [URL => $args->{request}->{url}->stringify],
                  [method => $args->{request}->{method}],
                  ['Expect-CT', 'abc'],
                  ['Public-key-Pins', 'ffa'],
                  ['Public-key-Pins-report-only', 'ffax'],
                  ['Upgrade', 'MySuperHTTP'],
                ],
                body_stream => $args->{request}->{body_stream},
                forwarding => 1,
              }};
            },
          });
          promised_cleanup { $ok->() } $con->completed;
        };
        $close_server = sub { undef $server };
      });

      my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
          ([{protocol => 'http', host => $host, port => $port}]);
      my $url = Web::URL->parse_string (qq{https://@{[$remote_host->to_ascii]}:$remote_port/} . rand);
      my $client = Web::Transport::BasicClient->new_from_url ($url, {
        proxy_manager => $pm,
        tls_options => {
          ca_cert => $ca_cert->to_pem,
        },
      });

      my $body = rand;
      promised_cleanup {
        done $c; undef $c;
      } promised_cleanup {
        return $server_p;
      } promised_cleanup {
        $close_server->();
      } promised_cleanup {
        return $client->close;
      } $client->request (
        url => $url,
        method => 'POST',
        body => $body,
      )->then (sub {
        my $res = $_[0];
        test {
          is $res->status, 208;
          is $res->status_text, 'abc';
          is $res->header ('server'), undef;
          ok $res->header ('date');
          is $res->header ('url'), $url->stringify;
          is $res->header ('method'), 'POST';
          is $res->header ('expect-ct'), 'abc';
          is $res->header ('public-key-pins'), 'ffa';
          is $res->header ('public-key-pins-report-only'), 'ffax';
          is $res->header ('upgrade'), 'MySuperHTTP';
          is $res->body_bytes, $body;
        } $c;
      });
    });
  });
} n => 11, name => 'mitm normal response by proxy';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;

  my $remote_host = Web::Host->parse_string (rand . '.test');
  my $remote_port = 3533;
  my $remote_host2 = Web::Host->parse_string (rand . '.test');
  ca_cert->then (sub {
    my ($ca_cert, $ca_rsa) = @{$_[0]};
    return ee_cert ($_[0], $remote_host)->then (sub {
      my ($ee_cert, $ee_rsa) = @{$_[0]};
      my $close_server;
      my $server_name = rand;
      my $exception_invoked = 0;
      my $server_p = Promise->new (sub {
        my ($ok) = @_;
        my $server = tcp_server $host, $port, sub {
          my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
            server_header => $server_name,
            handle_request => sub {
              my $args = $_[0];
              if ($args->{request}->{method} eq 'CONNECT') {
                $args->{upstream}->{type} = 'mitm';
                $args->{upstream}->{tls} = {
                  ca_cert => $ca_cert->to_pem,
                  cert => $ee_cert->to_pem,
                  key => $ee_rsa->to_pem,
                };
                return $args;
              }

              $args->{request}->{url} = Web::URL->parse_string (q<http://>.$remote_host2->to_ascii.q</>);
              return $args;
            },
          });
          $con->onexception (sub {
            my ($s, $x) = @_;
            test {
              isnt $s, $con;
              if ($exception_invoked == 0) {
                is $x->name, 'Protocol error', $x;
                is $x->message, "Target URL scheme is not |https|";
                is $x->file_name, __FILE__;
                is $x->line_number, __LINE__-9;
              } else {
                ## Downstream connection is closed by propagation of
                ## failure of upstream connection.
                is $x->name, 'TypeError', $x;
                is $x->message, "Response is not allowed";
                is $x->file_name, __FILE__;
                is $x->line_number, __LINE__-16;
              }
            } $c;
            $exception_invoked++;
            undef $con;
          });
          promised_cleanup { $ok->() } $con->completed;
        };
        $close_server = sub { undef $server };
      });

      my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
          ([{protocol => 'http', host => $host, port => $port}]);
      my $url = Web::URL->parse_string (qq{https://@{[$remote_host->to_ascii]}:$remote_port/} . rand);
      my $client = Web::Transport::BasicClient->new_from_url ($url, {
        proxy_manager => $pm,
        tls_options => {
          ca_cert => $ca_cert->to_pem,
        },
      });

      my $body = rand;
      promised_cleanup {
        done $c; undef $c;
      } promised_cleanup {
        return $server_p;
      } promised_cleanup {
        $close_server->();
      } promised_cleanup {
        return $client->close;
      } $client->request (
        url => $url,
        method => 'POST',
        body => $body,
      )->then (sub { test { ok 0 } $c }, sub {
        my $res = $_[0];
        test {
          ok $res->is_network_error;
          is $res->network_error_message, 'Connection closed without response';
          is $exception_invoked, 2;
        } $c;
      });
    });
  });
} n => 13, name => 'mitm upstream server is http, not allowed';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;

  my $host2;
  my $port2;

  my $remote_host = Web::Host->parse_string (rand . '.test');
  my $remote_port = 3533;

  my $server;
  rawserver (q{
    receive "POST"
    "HTTP/1.1 245 ok"CRLF
    "server: foo"CRLF
    CRLF
    "efg"
    close
  })->then (sub {
    $server = $_[0];
    $host2 = $server->{host};
    $port2 = $server->{port};
    return ca_cert;
  })->then (sub {
    my ($ca_cert, $ca_rsa) = @{$_[0]};
    return ee_cert ($_[0], $remote_host)->then (sub {
      my ($ee_cert, $ee_rsa) = @{$_[0]};
      my $close_server;
      my $server_name = rand;
      my $exception_invoked = 0;
      my $server_p = Promise->new (sub {
        my ($ok) = @_;
        my $server = tcp_server $host, $port, sub {
          my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
            server_header => $server_name,
            handle_request => sub {
              my $args = $_[0];
              if ($args->{request}->{method} eq 'CONNECT') {
                $args->{upstream}->{type} = 'mitm';
                $args->{upstream}->{tls} = {
                  ca_cert => $ca_cert->to_pem,
                  cert => $ee_cert->to_pem,
                  key => $ee_rsa->to_pem,
                };
                $args->{upstream}->{allow_downgrade} = 1;
                return $args;
              }

              $args->{request}->{url} = Web::URL->parse_string (q<http://>.$host2.":".$port2.q</>);
              return $args;
            },
          });
          $con->onexception (sub {
            my ($s, $x) = @_;
            test {
              isnt $s, $con;
              ok 0, $x;
            } $c;
            $exception_invoked++;
            undef $con;
          });
          $con->completed->finally (sub {
            $ok->();
            undef $con;
          });
        };
        $close_server = sub { undef $server };
      });

      my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
          ([{protocol => 'http', host => $host, port => $port}]);
      my $url = Web::URL->parse_string (qq{https://@{[$remote_host->to_ascii]}:$remote_port/} . rand);
      my $client = Web::Transport::BasicClient->new_from_url ($url, {
        proxy_manager => $pm,
        tls_options => {
          ca_cert => $ca_cert->to_pem,
        },
      });

      my $body = rand;
      promised_cleanup {
        done $c; undef $c;
      } promised_cleanup {
        return $server_p;
      } promised_cleanup {
        $close_server->();
      } promised_cleanup {
        return $client->close;
      } $client->request (
        url => $url,
        method => 'POST',
        body => $body,
      )->then (sub {
        my $res = $_[0];
        test {
          is $res->status, 245, $res;
          is $res->body_bytes, q{efg};
          ok ! $res->incomplete;
        } $c;
      }, sub {
        my $res = $_[0];
        test {
          is undef, $res;
        } $c;
      });
    });
  });
} n => 3, name => 'mitm upstream server is http, allowed';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;

  my $remote_host = Web::Host->parse_string (rand . '.test');
  my $remote_port = 3533;
  ca_cert->then (sub {
    my ($ca_cert, $ca_rsa) = @{$_[0]};
    return ee_cert ($_[0], $remote_host)->then (sub {
      my ($ee_cert, $ee_rsa) = @{$_[0]};
      my $close_server;
      my $server_name = rand;
      my $exception_invoked = 0;
      my $server_p = Promise->new (sub {
        my ($ok) = @_;
        my $server = tcp_server $host, $port, sub {
          my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
            server_header => $server_name,
            handle_request => sub {
              my $args = $_[0];
              if ($args->{request}->{method} eq 'CONNECT') {
                $args->{upstream}->{type} = 'mitm';
                $args->{upstream}->{tls} = {
                  ca_cert => $ca_cert->to_pem,
                  cert => $ee_cert->to_pem,
                  key => $ee_rsa->to_pem,
                };
                return $args;
              }
              return $args;
            },
          });
          $con->onexception (sub {
            my ($s, $x) = @_;
            test {
              isnt $s, $con;
              if ($exception_invoked == 0) {
                is $x->name, 'Protocol error', $x;
                is $x->message, "Can't resolve host |".$remote_host->to_ascii."|";
                is $x->file_name, __FILE__;
                is $x->line_number, __LINE__-9;
              } else {
                ## Downstream connection is closed by propagation of
                ## failure of upstream connection.
                is $x->name, 'TypeError', $x;
                is $x->message, "Response is not allowed";
                is $x->file_name, __FILE__;
                is $x->line_number, __LINE__-16;
              }
            } $c;
            $exception_invoked++;
            undef $con;
          });
          promised_cleanup { $ok->() } $con->completed;
        };
        $close_server = sub { undef $server };
      });

      my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
          ([{protocol => 'http', host => $host, port => $port}]);
      my $url = Web::URL->parse_string (qq{https://@{[$remote_host->to_ascii]}:$remote_port/} . rand);
      my $client = Web::Transport::BasicClient->new_from_url ($url, {
        proxy_manager => $pm,
        tls_options => {
          ca_cert => $ca_cert->to_pem,
        },
      });

      my $body = rand;
      promised_cleanup {
        done $c; undef $c;
      } promised_cleanup {
        return $server_p;
      } promised_cleanup {
        $close_server->();
      } promised_cleanup {
        return $client->close;
      } $client->request (
        url => $url,
        method => 'POST',
        body => $body,
      )->then (sub { test { ok 0 } $c }, sub {
        my $res = $_[0];
        test {
          ok $res->is_network_error;
          is $res->network_error_message, 'Connection closed without response';
          is $exception_invoked, 2;
        } $c;
      });
    });
  });
} n => 13, name => 'mitm upstream server network error';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;

  my $remote_host = '127.0.0.1';
  my $remote_port = find_listenable_port;
  Promise->all ([
    ca_cert, 
    ca_cert,
  ])->then (sub {
    my ($ca_cert, $ca_rsa) = @{$_[0]->[0]};
    my ($remote_ca_cert, $remote_ca_rsa) = @{$_[0]->[1]};
    return Promise->all ([
      ee_cert ($_[0]->[0], Web::Host->parse_string ($remote_host)),
      ee_cert ($_[0]->[1], Web::Host->parse_string ($remote_host)),
    ])->then (sub {
      my ($ee_cert, $ee_rsa) = @{$_[0]->[0]};
      my ($remote_ee_cert, $remote_ee_rsa) = @{$_[0]->[1]};
      my $exception_invoked = 0;

      my $close_server;
      my $server_name = rand;
      my $server_p = Promise->new (sub {
        my ($ok) = @_;
        my $server = tcp_server $host, $port, sub {
          my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
            client => {
              tls_options => {
                ca_cert => $remote_ca_cert->to_pem,
              },
            },
            server_header => $server_name,
            handle_request => sub {
              my $args = $_[0];
              if ($args->{request}->{method} eq 'CONNECT') {
                $args->{upstream}->{type} = 'mitm';
                $args->{upstream}->{tls} = {
                  ca_cert => $ca_cert->to_pem,
                  cert => $ee_cert->to_pem,
                  key => $ee_rsa->to_pem,
                };
                return $args;
              }
              return $args;
            },
          });
          $con->onexception (sub {
            $exception_invoked++;
          });
          promised_cleanup { $ok->() } $con->completed;
        };
        $close_server = sub { undef $server };
      });

      my $close_remote_server;
      my $remote_server_name = rand;
      my $remote_server_p = Promise->new (sub {
        my ($ok) = @_;
        my $remote_server = tcp_server $remote_host, $remote_port, sub {
          my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
            tls => {
              ca_cert => $remote_ca_cert->to_pem,
              cert => $remote_ee_cert->to_pem,
              key => $remote_ee_rsa->to_pem,
            },
            server_header => $remote_server_name,
            handle_request => sub {
              my $args = $_[0];
              return {response => {
                status => 208,
                status_text => "abc",
                headers => [
                  [URL => $args->{request}->{url}->stringify],
                  [method => $args->{request}->{method}],
                  ['Expect-CT', 'abc'],
                  ['Public-key-Pins', 'ffa'],
                  ['Public-key-Pins-report-only', 'ffax'],
                  ['Upgrade', 'MySuperHTTP'],
                ],
                body_stream => $args->{request}->{body_stream},
              }};
            },
          });
          $con->onexception (sub {
            $exception_invoked++;
          });
          promised_cleanup { $ok->() } $con->completed;
        };
        $close_remote_server = sub { undef $remote_server };
      });

      my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
          ([{protocol => 'http', host => $host, port => $port}]);
      my $url = Web::URL->parse_string (qq{https://$remote_host:$remote_port/} . rand);
      my $client = Web::Transport::BasicClient->new_from_url ($url, {
        proxy_manager => $pm,
        tls_options => {
          ca_cert => $ca_cert->to_pem,
        },
      });

      my $body = rand;
      promised_cleanup {
        done $c; undef $c;
      } promised_cleanup {
        return $server_p;
      } promised_cleanup {
        return $remote_server_p;
      } promised_cleanup {
        $close_server->();
      } promised_cleanup {
        $close_remote_server->();
      } promised_cleanup {
        return $client->close;
      } $client->request (
        url => $url,
        method => 'POST',
        body => $body,
      )->then (sub {
        my $res = $_[0];
        test {
          is $res->status, 208;
          is $res->status_text, 'abc';
          is $res->header ('Server'), $remote_server_name;
          is $res->header ('URL'), $url->stringify;
          is $res->header ('method'), 'POST';
          is $res->header ('expect-ct'), undef;
          is $res->header ('public-key-pins'), undef;
          is $res->header ('public-key-pins-report-only'), undef;
          is $res->header ('upgrade'), undef;
          is $res->body_bytes, $body;
          is $exception_invoked, 0;
        } $c;
      });
    });
  });
} n => 11, name => 'mitm upstream server remote origin server response';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;

  my $remote_host = '127.0.0.1';
  my $remote_port = find_listenable_port;
  Promise->all ([
    ca_cert, 
    ca_cert,
  ])->then (sub {
    my ($ca_cert, $ca_rsa) = @{$_[0]->[0]};
    my ($remote_ca_cert, $remote_ca_rsa) = @{$_[0]->[1]};
    return Promise->all ([
      ee_cert ($_[0]->[0], Web::Host->parse_string ($remote_host)),
      ee_cert ($_[0]->[1], Web::Host->parse_string ($remote_host)),
    ])->then (sub {
      my ($ee_cert, $ee_rsa) = @{$_[0]->[0]};
      my ($remote_ee_cert, $remote_ee_rsa) = @{$_[0]->[1]};
      my $exception_invoked = 0;

      my $close_server;
      my $server_name = rand;
      my $server_p = Promise->new (sub {
        my ($ok) = @_;
        my $server = tcp_server $host, $port, sub {
          my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
            client => {
              tls_options => {
                #ca_cert => $remote_ca_cert->to_pem,
              },
            },
            server_header => $server_name,
            handle_request => sub {
              my $args = $_[0];
              if ($args->{request}->{method} eq 'CONNECT') {
                $args->{upstream}->{type} = 'mitm';
                $args->{upstream}->{tls} = {
                  ca_cert => $ca_cert->to_pem,
                  cert => $ee_cert->to_pem,
                  key => $ee_rsa->to_pem,
                };
                return $args;
              }
              return $args;
            },
          });
          $con->onexception (sub {
            my ($s, $x) = @_;
            test {
              isnt $s, $con;
              if ($exception_invoked == 0) {
                is $x->name, 'Protocol error', $x;
                my $m = $x->message;
                $m =~ s/self-signed/self signed/g;
                is $m, "Certificate verification error 19 - self signed certificate in certificate chain";
                is $x->file_name, __FILE__;
                is $x->line_number, __LINE__-11;
              } else {
                ## Downstream connection is closed by propagation of
                ## failure of upstream connection.
                is $x->name, 'TypeError', $x;
                is $x->message, "Response is not allowed";
                is $x->file_name, __FILE__;
                is $x->line_number, __LINE__-18;
              }
            } $c;
            $exception_invoked++;
            undef $con;
          });
          promised_cleanup { $ok->() } $con->completed;
        };
        $close_server = sub { undef $server };
      });

      my $close_remote_server;
      my $remote_server_name = rand;
      my $remote_server_p = Promise->new (sub {
        my ($ok) = @_;
        my $remote_server = tcp_server $remote_host, $remote_port, sub {
          my $con = Web::Transport::ProxyServerConnection->new_from_aeargs_and_opts ([@_], {
            tls => {
              ca_cert => $remote_ca_cert->to_pem,
              cert => $remote_ee_cert->to_pem,
              key => $remote_ee_rsa->to_pem,
            },
            server_header => $remote_server_name,
            handle_request => sub {
              my $args = $_[0];
              return {response => {
                status => 208,
                status_text => "abc",
                headers => [
                  [URL => $args->{request}->{url}->stringify],
                  [method => $args->{request}->{method}],
                ],
                body_stream => $args->{request}->{body_stream},
              }};
            },
          });
          $con->onexception (sub {
            $exception_invoked++;
          });
          promised_cleanup { $ok->() } $con->completed;
        };
        $close_remote_server = sub { undef $remote_server };
      });

      my $pm = Web::Transport::ConstProxyManager->new_from_arrayref
          ([{protocol => 'http', host => $host, port => $port}]);
      my $url = Web::URL->parse_string (qq{https://$remote_host:$remote_port/} . rand);
      my $client = Web::Transport::BasicClient->new_from_url ($url, {
        proxy_manager => $pm,
        tls_options => {
          ca_cert => $ca_cert->to_pem,
        },
      });

      my $body = rand;
      promised_cleanup {
        done $c; undef $c;
      } promised_cleanup {
        return $server_p;
      } promised_cleanup {
        return $remote_server_p;
      } promised_cleanup {
        $close_server->();
      } promised_cleanup {
        $close_remote_server->();
      } promised_cleanup {
        return $client->close;
      } $client->request (
        url => $url,
        method => 'POST',
        body => $body,
      )->then (sub { test { ok 0 } $c }, sub {
        my $res = $_[0];
        test {
          ok $res->is_network_error;
          is $res->network_error_message, 'Connection closed without response';
          is $exception_invoked, 2;
        } $c;
      });
    });
  });
} n => 13, name => 'mitm upstream server remote origin server TLS error';

run_tests;

=head1 LICENSE

Copyright 2016-2024 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
