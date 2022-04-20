use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->child ('t_deps/lib');
use lib glob path (__FILE__)->parent->parent->child ('t_deps/modules/*/lib');
use Test::More;
use Test::X1;
use Test::HTCT::Parser;
use Test::Certificates;
use Web::Host;
use Web::Transport::TCPTransport;
use Web::Transport::H1CONNECTTransport;
use Web::Transport::TLSTransport;
use Web::Transport::UNIXDomainSocketTransport;
use Web::Transport::HTTPClientConnection;
use Promise;
use AnyEvent::Util qw(run_cmd);
use Web::Transport::FindPort;

my $server_pids = {};
END { kill 'KILL', $_ for keys %$server_pids }
sub _server_as_cv ($$$) {
  my ($host, $port, $code) = @_;
  my $cv = AE::cv;
  my $started;
  my $pid;
  my $data = '';
  my $run_cv = run_cmd
      ['perl', path (__FILE__)->parent->parent->child ('t_deps/server.pl'), $host, $port],
      '<' => \$code,
      '>' => sub {
        $data .= $_[0] if defined $_[0];
        return if $started;
        if ($data =~ /^\[server (\S+) (\S+)\]/m) {
          $cv->send ({pid => $pid, addr => $1, port => $2,
                      stop => sub {
                        kill 'TERM', $pid;
                        delete $server_pids->{$pid};
                      }});
          $started = 1;
        }
      },
      '$$' => \$pid;
  $server_pids->{$pid} = 1;
  $run_cv->cb (sub {
    my $result = $_[0]->recv;
    if ($result) {
      $cv->croak ("Server error: $result") unless $started;
    }
  });
  return $cv;
} # _server_as_cv

sub server_as_cv ($) {
  return _server_as_cv ('127.0.0.1', find_listenable_port, $_[0]);
} # server_as_cv

my $test_path = path (__FILE__)->parent->parent->child ('local/test')->absolute;
$test_path->mkpath;

sub unix_server_as_cv ($) {
  return _server_as_cv ('unix/', $test_path->child (int (rand 10000) + 1024), $_[0]);
} # unix_server_as_cv

test {
  my $c = shift;
  my $tcp = Web::Transport::TCPTransport->new
      (host => Web::Host->parse_string ('127.0.53.53'), port => rand);
  my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
  my $p = $http->send_request_headers ({method => 'GET', target => '/'});
  isa_ok $p, 'Promise';
  $p->then (sub {
    test {
      ok 0;
    } $c;
  }, sub {
    my $e = $_[0];
    test {
      is $e, 'Connection has not been established';
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 2, name => 'not connected';

test {
  my $c = shift;
  server_as_cv (q{
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'GET', target => '/'});
    })->then (sub {
      my $p = $http->send_request_headers ({method => 'GET', target => '/'});
      test {
        isa_ok $p, 'Promise';
      } $c;
      return $p->then (sub {
        test { ok 0 } $c;
      }, sub {
        my $e = $_[0];
        test {
          is $e, 'Connection is no longer in active';
        } $c;
      });
    })->then (sub{
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => 'connection already closed';

test {
  my $c = shift;
  server_as_cv (q{
    sleep 1
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    $http->connect->then (sub {
      my $p1 = $http->send_request_headers ({method => 'GET', target => '/'});
      my $p = $http->send_request_headers ({method => 'GET', target => '/'});
      test {
        isa_ok $p, 'Promise';
      } $c;
      return $p->then (sub {
        test { ok 0 } $c;
      }, sub {
        my $e = $_[0];
        test {
          is $e, 'Connection is busy';
        } $c;
      });
    })->then (sub{
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => 'connection already closed';


test {
  my $c = shift;
  server_as_cv (q{
    sleep 1
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    $http->connect->then (sub {
      my @p;
      for my $subtest (
        [['' => 'abc']],
        [['[]' => 'abc']],
        [["\x{100}" => 'abc']],
        [['Hoge' => "abc \x0A"]],
        [['Hoge' => "abc \x0Db"]],
        [['Hoge' => "\x0D\x0A"]],
        [['Hoge' => "\x{4000}"]],
      ) {
        push @p, Promise->resolve->then (sub {
          $http->send_request_headers
              ({method => 'GET', target => '/',
                headers => $subtest});
        })->catch (sub {
          my $error = $_[0];
          test {
            like $error, qr{Bad header };
          } $c;
        });
      }
    })->then (sub{
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 7, name => 'send_request_headers with bad headers';

test {
  my $c = shift;
  server_as_cv (q{
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    my $error;
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'GET', target => '/'}, cb => sub {
        my ($http, $type, $data) = @_;
        $error = $data if $type eq 'complete';
      });
    })->then (sub {
      test {
        ok not $error->{can_retry};
      } $c;
    })->then (sub{
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'first empty response';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET"
    "HTTP/1.1 200 OK"CRLF
    "Content-Length: 0"CRLF
    CRLF
    receive "GET"
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    my $error;
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'GET', target => '/'}, cb => sub {
        my ($http, $type, $data) = @_;
        $error = $data if $type eq 'complete';
      });
    })->then (sub {
      return $http->send_request_headers ({method => 'GET', target => '/'}, cb => sub {
        my ($http, $type, $data) = @_;
        $error = $data if $type eq 'complete';
      });
    })->then (sub {
      test {
        ok $error->{can_retry};
      } $c;
    })->then (sub{
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'second empty response';

for my $tbmethod (qw(send_text_header send_binary_header)) {

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET"
    "HTTP/1.1 200 OK"CRLF
    "Content-Length: 0"CRLF
    CRLF
    receive "GET"
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    $http->connect->then (sub {
      $http->$tbmethod (3);
      $http->send_data (\'abc');
    })->then (sub {
      test { ok 0 } $c;
    }, sub {
      my $error = $_[0];
      test {
        like $error, qr{^Bad state};
      } $c;
    })->then (sub{
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => ['send_ws_message before request', $tbmethod];

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET"
    "HTTP/1.1 200 OK"CRLF
    "Content-Length: 0"CRLF
    CRLF
    receive "GET"
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    my $error;
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'GET', target => '/'}, ws => 1, cb => sub {
        my ($http, $type, $data) = @_;
        $error = $data->{reason} if $type eq 'complete';
      });
    })->then (sub {
      $http->$tbmethod (3);
      $http->send_data (\'abc');
    })->then (sub {
      test { ok 0 } $c;
    }, sub {
      my $error = $_[0];
      test {
        like $error, qr{^Bad state};
      } $c;
    })->then (sub{
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => ['send_ws_message after bad handshake', $tbmethod];

test {
  my $c = shift;
  server_as_cv (q{
receive "GET", start capture
receive CRLFCRLF, end capture
"HTTP/1.1 101 OK"CRLF
"Upgrade: websocket"CRLF
"Sec-WebSocket-Accept: "
ws-accept
CRLF
"Connection: Upgrade"CRLF
CRLF
ws-receive-header
ws-receive-data
ws-send-header opcode=1 length=3
"xyz"
close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    my $sent = 0;
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'GET', target => '/'}, ws => 1, cb => sub {
        my ($http, $type, $data) = @_;
        if ($type eq 'headers') {
          $http->$tbmethod (3);
          $http->send_data (\'abc');
          $sent++;
        }
      });
    })->then (sub{
      test {
        is $sent, 1;
      } $c;
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => ['send_ws_message ok', $tbmethod];

test {
  my $c = shift;
  server_as_cv (q{
receive "GET", start capture
receive CRLFCRLF, end capture
"HTTP/1.1 101 OK"CRLF
"Upgrade: websocket"CRLF
"Sec-WebSocket-Accept: "
ws-accept
CRLF
"Connection: Upgrade"CRLF
CRLF
sleep 1
close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    my $error = 0;
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'GET', target => '/'}, ws => 1, cb => sub {
        my ($http, $type, $data) = @_;
        if ($type eq 'headers') {
          $http->$tbmethod (2);
          eval {
            $http->send_data (\'abc');
          } or do {
            test {
              like $@, qr{^Data too large};
            } $c;
            $error++;
          }
        }
      });
    })->then (sub{
      test {
        is $error, 1;
      } $c;
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => ['send_ws_message data too large', $tbmethod];

test {
  my $c = shift;
  server_as_cv (q{
receive "GET", start capture
receive CRLFCRLF, end capture
"HTTP/1.1 101 OK"CRLF
"Upgrade: websocket"CRLF
"Sec-WebSocket-Accept: "
ws-accept
CRLF
"Connection: Upgrade"CRLF
CRLF
sleep 1
close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    my $error = 0;
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'GET', target => '/'}, ws => 1, cb => sub {
        my ($http, $type, $data) = @_;
        if ($type eq 'headers') {
          $http->$tbmethod (2);
          eval {
            $http->send_data (\"\x{100}");
          } or do {
            test {
              like $@, qr{^Data is utf8-flagged};
            } $c;
            $error++;
          }
        }
      });
    })->then (sub{
      test {
        is $error, 1;
      } $c;
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => ['send_ws_message data utf8 flagged', $tbmethod];

test {
  my $c = shift;
  server_as_cv (q{
receive "GET", start capture
receive CRLFCRLF, end capture
"HTTP/1.1 101 OK"CRLF
"Upgrade: websocket"CRLF
"Sec-WebSocket-Accept: "
ws-accept
CRLF
"Connection: Upgrade"CRLF
CRLF
sleep 1
close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    my $error = 0;
    my @p;
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'GET', target => '/'}, ws => 1, cb => sub {
        my ($http, $type, $data) = @_;
        if ($type eq 'headers') {
          $http->$tbmethod (3);
          $http->send_data (\'ab');
          for my $code (
            sub { $http->send_text_header (4); },
            sub { $http->send_binary_header (4); },
            sub { $http->send_ping },
            sub { $http->send_ping (pong => 1) },
            sub { $http->close },
          ) {
            push @p,
            Promise->resolve->then ($code)->then (sub { test { ok 0 } $c }, sub {
              my $err = $_[0];
              test {
                like $err, qr{^(?:Bad state|Body is not sent)};
              } $c;
              $error++;
            });
          }
        }
      });
    })->then (sub{
      test {
        is $error, 5;
      } $c;
      return Promise->all (\@p);
    })->then (sub {
      return $http->abort;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 6, name => ['send_ws_message then bad method', $tbmethod];

test {
  my $c = shift;
  server_as_cv (q{
receive "GET", start capture
receive CRLFCRLF, end capture
"HTTP/1.1 101 OK"CRLF
"Upgrade: websocket"CRLF
"Sec-WebSocket-Accept: "
ws-accept
CRLF
"Connection: Upgrade"CRLF
CRLF
ws-receive-header
ws-receive-header
ws-receive-data
ws-receive-header
ws-send-header opcode=1 length=3
"xyz"
close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    my $sent = 0;
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'GET', target => '/'}, ws => 1, cb => sub {
        my ($http, $type, $data) = @_;
        if ($type eq 'headers') {
          $http->$tbmethod (0);
          $http->$tbmethod (3);
          $http->send_data (\'a');
          $http->send_data (\'bc');
          $http->$tbmethod (0);
          $sent++;
        }
      });
    })->then (sub{
      test {
        is $sent, 1;
      } $c;
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => ['send_ws_message zero length', $tbmethod];

}

test {
  my $c = shift;
  server_as_cv (q{
receive "GET", start capture
receive CRLFCRLF, end capture
"HTTP/1.1 101 OK"CRLF
"Upgrade: websocket"CRLF
"Sec-WebSocket-Accept: "
ws-accept
CRLF
"Connection: Upgrade"CRLF
CRLF
ws-receive-header
ws-receive-data
ws-send-header opcode=1 length=3
"xyz"
close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    my $sent = 0;
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'GET', target => '/'}, ws => 1, cb => sub {
        my ($http, $type, $data) = @_;
        if ($type eq 'headers') {
          $http->close;
          $sent++;
        }
      });
    })->then (sub{
      test {
        is $sent, 1;
      } $c;
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'ws close ok no args';

test {
  my $c = shift;
  server_as_cv (q{
receive "GET", start capture
receive CRLFCRLF, end capture
"HTTP/1.1 101 OK"CRLF
"Upgrade: websocket"CRLF
"Sec-WebSocket-Accept: "
ws-accept
CRLF
"Connection: Upgrade"CRLF
CRLF
ws-receive-header
ws-receive-data
ws-send-header opcode=1 length=3
"xyz"
close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    my $sent = 0;
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'GET', target => '/'}, ws => 1, cb => sub {
        my ($http, $type, $data) = @_;
        if ($type eq 'headers') {
          $http->close (status => 1234);
          $sent++;
        }
      });
    })->then (sub{
      test {
        is $sent, 1;
      } $c;
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'ws close ok with status';

test {
  my $c = shift;
  server_as_cv (q{
receive "GET", start capture
receive CRLFCRLF, end capture
"HTTP/1.1 101 OK"CRLF
"Upgrade: websocket"CRLF
"Sec-WebSocket-Accept: "
ws-accept
CRLF
"Connection: Upgrade"CRLF
CRLF
ws-receive-header
ws-receive-data
ws-send-header opcode=1 length=3
"xyz"
close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    my $sent = 0;
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'GET', target => '/'}, ws => 1, cb => sub {
        my ($http, $type, $data) = @_;
        if ($type eq 'headers') {
          $http->close (status => 1234, reason => 'av c');
          $sent++;
        }
      });
    })->then (sub{
      test {
        is $sent, 1;
      } $c;
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'ws close ok with status and reason';

test {
  my $c = shift;
  server_as_cv (q{
receive "GET", start capture
receive CRLFCRLF, end capture
"HTTP/1.1 101 OK"CRLF
"Upgrade: websocket"CRLF
"Sec-WebSocket-Accept: "
ws-accept
CRLF
"Connection: Upgrade"CRLF
CRLF
ws-receive-header
ws-receive-data
ws-send-header opcode=1 length=3
"xyz"
close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    my $sent = 0;
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'GET', target => '/'}, ws => 1, cb => sub {
        my ($http, $type, $data) = @_;
        if ($type eq 'headers') {
          $http->close (status => 0x10000, reason => 'av c')->then (sub {
            test { ok 0 } $c;
          }, sub {
            my $err = $_[0];
            test {
              like $err, qr{^Bad status};
            } $c;
          })->then (sub { return $http->close });
          $sent++;
        }
      });
    })->then (sub{
      test {
        is $sent, 1;
      } $c;
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => 'ws close with bad status';

test {
  my $c = shift;
  server_as_cv (q{
receive "GET", start capture
receive CRLFCRLF, end capture
"HTTP/1.1 101 OK"CRLF
"Upgrade: websocket"CRLF
"Sec-WebSocket-Accept: "
ws-accept
CRLF
"Connection: Upgrade"CRLF
CRLF
ws-receive-header
ws-receive-data
ws-send-header opcode=1 length=3
"xyz"
close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    my $sent = 0;
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'GET', target => '/'}, ws => 1, cb => sub {
        my ($http, $type, $data) = @_;
        if ($type eq 'headers') {
          $http->close (status => 1234, reason => "\x{105}")->then (sub {
            test { ok 0 } $c;
          }, sub {
            my $err = $_[0];
            test {
              like $err, qr{^Reason is utf8-flagged};
            } $c;
          })->then (sub { return $http->close });
          $sent++;
        }
      });
    })->then (sub{
      test {
        is $sent, 1;
      } $c;
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => 'ws close with bad reason';

test {
  my $c = shift;
  server_as_cv (q{
receive "GET", start capture
receive CRLFCRLF, end capture
"HTTP/1.1 101 OK"CRLF
"Upgrade: websocket"CRLF
"Sec-WebSocket-Accept: "
ws-accept
CRLF
"Connection: Upgrade"CRLF
CRLF
ws-receive-header
ws-receive-data
ws-send-header opcode=1 length=3
"xyz"
close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    my $sent = 0;
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'GET', target => '/'}, ws => 1, cb => sub {
        my ($http, $type, $data) = @_;
        if ($type eq 'headers') {
          $http->close (status => 1234, reason => 'x' x 126)->then (sub {
            test { ok 0 } $c;
          }, sub {
            my $err = $_[0];
            test {
              like $err, qr{^Reason is too long};
            } $c;
          })->then (sub { return $http->close });
          $sent++;
        }
      });
    })->then (sub{
      test {
        is $sent, 1;
      } $c;
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => 'ws close with long reason';

test {
  my $c = shift;
  server_as_cv (q{
receive "GET", start capture
receive CRLFCRLF, end capture
"HTTP/1.1 200 OK"CRLF
CRLF
"abc"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    my $sent = 0;
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'GET', target => '/'}, cb => sub {
        my ($http, $type, $data) = @_;
        if ($type eq 'headers') {
          AE::postpone {
            $http->abort;
            $sent++;
          };
        }
      });
    })->then (sub{
      test {
        is $sent, 1, "abort called";
      } $c;
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    }, sub {
      warn $_[0];
    });
  });
} n => 1, name => 'headers then abort';

test {
  my $c = shift;
  server_as_cv (q{
receive "GET", start capture
receive CRLFCRLF, end capture
"HTTP/1.1 101 OK"CRLF
"Upgrade: websocket"CRLF
"Sec-WebSocket-Accept: "
ws-accept
CRLF
"Connection: Upgrade"CRLF
CRLF
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    my $sent = 0;
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'GET', target => '/'}, ws => 1, cb => sub {
        my ($http, $type, $data) = @_;
        if ($type eq 'headers') {
          AE::postpone {
            $http->abort;
            $sent++;
          };
        }
      });
    })->then (sub{
      test {
        is $sent, 1, "abort called";
      } $c;
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    }, sub {
      warn $_[0];
    });
  });
} n => 1, name => 'ws then abort';

test {
  my $c = shift;
  server_as_cv (q{
receive "GET", start capture
receive CRLFCRLF, end capture
"HTTP/1.1 101 OK"CRLF
"Upgrade: websocket"CRLF
"Sec-WebSocket-Accept: "
ws-accept
CRLF
"Connection: Upgrade"CRLF
CRLF
ws-receive-header
ws-receive-data
ws-send-header opcode=10 length=3
"xyz"
close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    my $sent = 0;
    my $pong = 0;
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'GET', target => '/'}, ws => 1, cb => sub {
        my ($http, $type, $data) = @_;
        if ($type eq 'headers') {
          $http->send_ping;
          $sent++;
        } elsif ($type eq 'ping') {
          $pong++;
        }
      });
    })->then (sub{
      test {
        is $sent, 1;
        is $pong, 1;
      } $c;
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => 'ws ping';

test {
  my $c = shift;
  server_as_cv (q{
receive "GET", start capture
receive CRLFCRLF, end capture
"HTTP/1.1 101 OK"CRLF
"Upgrade: websocket"CRLF
"Sec-WebSocket-Accept: "
ws-accept
CRLF
"Connection: Upgrade"CRLF
CRLF
ws-receive-header
ws-receive-data
ws-send-header opcode=10 length=3
"xyz"
close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    my $sent = 0;
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'GET', target => '/'}, ws => 1, cb => sub {
        my ($http, $type, $data) = @_;
        if ($type eq 'headers') {
          $http->send_ping (pong => 1);
          $sent++;
        }
      });
    })->then (sub{
      test {
        is $sent, 1;
      } $c;
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'ws ping pong';

test {
  my $c = shift;
  server_as_cv (q{
receive "GET", start capture
receive CRLFCRLF, end capture
"HTTP/1.1 101 OK"CRLF
"Upgrade: websocket"CRLF
"Sec-WebSocket-Accept: "
ws-accept
CRLF
"Connection: Upgrade"CRLF
CRLF
ws-receive-header
ws-receive-data
ws-send-header opcode=10 length=3
"xyz"
close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    my $sent = 0;
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'GET', target => '/'}, ws => 1, cb => sub {
        my ($http, $type, $data) = @_;
        if ($type eq 'headers') {
          $http->send_ping (data => "ab c");
          $sent++;
        }
      });
    })->then (sub{
      test {
        is $sent, 1;
      } $c;
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'ws ping data';

test {
  my $c = shift;
  server_as_cv (q{
receive "GET", start capture
receive CRLFCRLF, end capture
"HTTP/1.1 101 OK"CRLF
"Upgrade: websocket"CRLF
"Sec-WebSocket-Accept: "
ws-accept
CRLF
"Connection: Upgrade"CRLF
CRLF
ws-receive-header
ws-receive-data
ws-send-header opcode=10 length=3
"xyz"
close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    my $error = 0;
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'GET', target => '/'}, ws => 1, cb => sub {
        my ($http, $type, $data) = @_;
        if ($type eq 'headers') {
          eval {
            $http->send_ping (data => "ab c\x{500}");
          } or do {
            test {
              like $@, qr{^Data is utf8-flagged};
              $error++;
            } $c;
          };
          $http->close;
        }
      });
    })->then (sub{
      test {
        is $error, 1;
      } $c;
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => 'ws ping utf8 data';

test {
  my $c = shift;
  server_as_cv (q{
receive "GET", start capture
receive CRLFCRLF, end capture
"HTTP/1.1 101 OK"CRLF
"Upgrade: websocket"CRLF
"Sec-WebSocket-Accept: "
ws-accept
CRLF
"Connection: Upgrade"CRLF
CRLF
ws-receive-header
ws-receive-data
ws-send-header opcode=10 length=3
"xyz"
close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    my $error = 0;
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'GET', target => '/'}, ws => 1, cb => sub {
        my ($http, $type, $data) = @_;
        if ($type eq 'headers') {
          eval {
            $http->send_ping (data => 'x' x 126);
          } or do {
            test {
              like $@, qr{^Data too large};
              $error++;
            } $c;
          };
          $http->close;
        }
      });
    })->then (sub{
      test {
        is $error, 1;
      } $c;
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => 'ws ping long data';

test {
  my $c = shift;
  server_as_cv (q{
receive "GET", start capture
receive CRLFCRLF, end capture
"HTTP/1.1 101 OK"CRLF
"Upgrade: websocket"CRLF
"Sec-WebSocket-Accept: "
ws-accept
CRLF
"Connection: Upgrade"CRLF
CRLF
ws-receive-header
ws-receive-data
ws-send-header opcode=10 length=3
"xyz"
close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    my $error = 0;
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'GET', target => '/'}, ws => 1, cb => sub {
        my ($http, $type, $data) = @_;
        if ($type eq 'headers') {
          $http->close->then (sub {
            $http->send_ping (data => 'x');
          })->then (sub {
            test { ok 0 } $c;
          }, sub {
            my $err = $_[0];
            test {
              like $err, qr{^Bad state}, 'error text';
              $error++;
            } $c;
          });
        }
      });
    })->then (sub{
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'ws ping after closed';

test {
  my $c = shift;
  server_as_cv (q{
receive "GET", start capture
receive CRLFCRLF, end capture
"HTTP/1.1 101 OK"CRLF
"Upgrade: websocket"CRLF
"Sec-WebSocket-Accept: "
ws-accept
CRLF
"Connection: Upgrade"CRLF
CRLF
ws-receive-header
ws-receive-data
sleep 21
ws-send-header opcode=9 length=3
"xyz"
close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    my $ping = 0;
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'GET', target => '/'}, ws => 1, cb => sub {
        my ($http, $type, $data) = @_;
        if ($type eq 'headers') {
          $http->close;
        } elsif ($type eq 'ping') {
          $ping++;
        }
      });
    })->then (sub{
      return $http->close;
    })->then (sub {
      test {
        is $ping, 0, 'ping not received';
      } $c;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'ws ping received after closed';

test {
  my $c = shift;
  server_as_cv (q{
receive "GET", start capture
receive CRLFCRLF, end capture
"HTTP/1.1 101 OK"CRLF
"Upgrade: websocket"CRLF
"Sec-WebSocket-Accept: "
ws-accept
CRLF
"Connection: Upgrade"CRLF
CRLF
ws-receive-header
ws-receive-data
ws-send-header opcode=10 length=3
"xyz"
close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    my $error = 0;
    $http->connect->then (sub {
      return $http->send_ping;
    })->then (sub{
      test { ok 0 } $c;
    }, sub {
      my $err = $_[0];
      test {
        like $err, qr{^Bad state}, 'error text';
        $error++;
      } $c;
    })->then (sub {
      test {
        is $error, 1, 'error count';
      } $c;
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => 'ws ping bad context';

test {
  my $c = shift;
  server_as_cv (q{
receive "CONNECT"
"HTTP/1.1 200 OK"CRLF
CRLF
"xyz"
close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    my $sent = 0;
    my $received = '';
    my @ev;
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'CONNECT', target => 'test'}, cb => sub {
        my ($http, $type, $data) = @_;
        push @ev, $type if $type eq 'complete';
        if ($type eq 'headers') {
          AE::postpone {
            test {
              $http->send_data (\'abc');
              $http->close;
              $sent++;
            } $c;
          };
        } elsif ($type eq 'data') {
          $received .= $data;
        }
      });
    })->then (sub{
      test {
        is $sent, 1;
        is $received, 'xyz';
        is $ev[-1], 'complete';
        pop @ev;
      } $c;
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 3, name => 'connect';

test {
  my $c = shift;
  server_as_cv (q{
receive "CONNECT"
"HTTP/1.1 200 OK"CRLF
CRLF
"xyz"
close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    my $sent = 0;
    my $received = '';
    my @ev;
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'CONNECT', target => 'test'}, cb => sub {
        my ($http, $type, $data) = @_;
        push @ev, $type if $type eq 'complete';
        if ($type eq 'headers') {
          AE::postpone {
            test {
              eval {
                $http->send_data (\"\x{5000}");
              };
              like $@, qr{^Data is utf8-flagged};
            } $c;
          };
          AE::postpone {
            test {
              $http->send_data (\'abc');
              $http->close;
              $sent++;
            } $c;
          };
        } elsif ($type eq 'data') {
          $received .= $data;
        }
      });
    })->then (sub{
      test {
        is $sent, 1;
        is $received, 'xyz';
        is $ev[-1], 'complete';
        pop @ev;
      } $c;
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 4, name => 'connect send_data utf8';

test {
  my $c = shift;
  server_as_cv (q{
receive "CONNECT"
"HTTP/1.1 200 OK"CRLF
CRLF
"xyz"
close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    my $sent = 0;
    my $received = '';
    my @ev;
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'CONNECT', target => 'test'}, cb => sub {
        my ($http, $type, $data) = @_;
        push @ev, $type if $type eq 'complete';
        if ($type eq 'headers') {
          AE::postpone {
            test {
              $http->send_data (\'');
              $http->close;
              $sent++;
            } $c;
          };
        } elsif ($type eq 'data') {
          $received .= $data;
        }
      });
    })->then (sub{
      test {
        is $sent, 1;
        is $received, 'xyz';
        is $ev[-1], 'complete';
        pop @ev;
      } $c;
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 3, name => 'connect send_data empty';

test {
  my $c = shift;
  server_as_cv (q{
receive "CONNECT"
"HTTP/1.1 200 OK"CRLF
CRLF
"xyz"
close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    my $error = 0;
    my $x;
    my $p = Promise->new (sub { $x = $_[0] });
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'CONNECT', target => 'test'}, cb => sub {
        my ($http, $type, $data) = @_;
        if ($type eq 'headers') {
          AE::postpone {
            $http->close->then (sub {
              $http->send_data (\'abc');
            })->then (sub {
              test { ok 0 } $c;
            }, sub {
              my $err = $_[0];
              test {
                like $err, qr{^Bad state};
                $x->();
              } $c;
            });
          };
        }
      });
    })->then (sub{
      return $p;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'connect data after close';

test {
  my $c = shift;
  server_as_cv (q{
receive "CONNECT"
"HTTP/1.1 200 OK"CRLF
CRLF
show "sleep"
sleep 1
"xyz"
close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    my $received = '';
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'CONNECT', target => 'test'}, cb => sub {
        my ($http, $type, $data) = @_;
        if ($type eq 'headers') {
          $received .= '(headers)';
          AE::postpone {
            $http->close;
          };
        } elsif ($type eq 'data') {
          $received .= $data;
        }
      });
    })->then (sub{
      test {
        is $received, '(headers)xyz';
      } $c;
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'connect received after send-shutdown';

test {
  my $c = shift;
  server_as_cv (q{
receive "CONNECT"
"HTTP/1.1 200 OK"CRLF
CRLF
close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'CONNECT', target => 'test'}, cb => sub {
        my ($http, $type, $data) = @_;
        if ($type eq 'headers') {
          my $timer; $timer = AE::timer 1, 0, sub {
            $http->send_data (\'abc');
            AE::postpone {
              $http->close;
            };
            undef $timer;
          };
        }
      });
    })->then (sub{
      test {
        ok 1;
      } $c;
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'connect sending after EOF';

test {
  my $c = shift;
  server_as_cv (q{
receive "hoge"
"HTTP/1.1 200 OK"CRLF
"Content-Length: 2"CRLF
CRLF
"OK"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    $http->connect->then (sub {
      my $p = $http->send_request_headers
          ({method => 'GET', target => 'test',
            headers => [['Content-Length' => 4]]}, cb => sub {
        my ($http, $type, $data) = @_;
        if ($type eq 'data') {
          test {
            is $data, 'OK';
          } $c;
        }
      });
      $http->send_data (\"hoge");
      return $p;
    })->then (sub {
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'with request body';

test {
  my $c = shift;
  server_as_cv (q{
receive "hoge"
"HTTP/1.1 200 OK"CRLF
"Content-Length: 2"CRLF
CRLF
"NG"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    $http->connect->then (sub {
      my $p = $http->send_request_headers
          ({method => 'GET', target => 'test',
            headers => [['Content-Length' => 4]]},
           cb => sub {
        my ($http, $type, $data) = @_;
        if ($type eq 'data') {
          test {
            ok 0;
          } $c;
        }
      });
      test {
        eval {
          $http->send_data (\"hoge!");
        } or do {
          like $@, qr/^Data too large/;
          $http->abort;
        };
      } $c;
      return $p;
    })->then (sub {
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'with request body - too long 1';

test {
  my $c = shift;
  server_as_cv (q{
receive "hoge"
"HTTP/1.1 200 OK"CRLF
"Content-Length: 2"CRLF
CRLF
"NG"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    $http->connect->then (sub {
      my $p = $http->send_request_headers
          ({method => 'GET', target => 'test',
            headers => [['Content-Length' => 4]]}, cb => sub {
        my ($http, $type, $data) = @_;
        if ($type eq 'data') {
          test {
            ok 0;
          } $c;
        }
      });
      $http->send_data (\"ho");
      test {
        eval {
          $http->send_data (\"ge!");
        } or do {
          like $@, qr/^Data too large/;
          $http->abort;
        };
      } $c;
      return $p;
    })->then (sub {
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'with request body - too long 2';

test {
  my $c = shift;
  server_as_cv (q{
receive "hoge"
"HTTP/1.1 200 OK"CRLF
"Content-Length: 2"CRLF
CRLF
"NG"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    $http->connect->then (sub {
      my $p = $http->send_request_headers
          ({method => 'GET', target => 'test',
            headers => [['Content-Length' => 0]]}, cb => sub {
        my ($http, $type, $data) = @_;
        if ($type eq 'data') {
          test {
            ok 0;
          } $c;
        }
      });
      test {
        eval {
          $http->send_data (\"hoge");
        } or do {
          like $@, qr/^Bad state/;
          $http->abort;
        };
      } $c;
      return $p;
    })->then (sub {
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'with request body - not allowed';

test {
  my $c = shift;
  server_as_cv (q{
receive "hoge"
"HTTP/1.1 200 OK"CRLF
"Content-Length: 0"CRLF
CRLF
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    $http->connect->then (sub {
      my $p = $http->send_request_headers
          ({method => 'GET', target => 'test',
            headers => [['Content-Length' => 4]]},
           cb => sub {});
      return $http->close->catch (sub {
        my $err = $_[0];
        test {
          like $err, qr{^Body is not sent};
        } $c;
        return $http->send_data (\'hoge');
      })->then (sub { return $p });
    })->then (sub {
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'with request body - closed without body';

test {
  my $c = shift;
  server_as_cv (q{
receive "hoge"
"HTTP/1.1 200 OK"CRLF
"Content-Length: 2"CRLF
CRLF
"NG"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    $http->connect->then (sub {
      my $p = $http->send_request_headers
          ({method => 'GET', target => 'test',
            headers => [['Content-Length' => 4]]},
           cb => sub {
        my ($http, $type, $data) = @_;
        if ($type eq 'data') {
          test {
            ok 0;
          } $c;
        }
      });
      test {
        eval {
          $http->send_data (\"ge\x{500}");
        } or do {
          like $@, qr/^Data is utf8-flagged/;
          $http->abort;
        };
      } $c;
      return $p;
    })->then (sub {
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'with request body - utf8';

test {
  my $c = shift;
  server_as_cv (q{
receive "CONNECT"
"HTTP/1.1 200 OK"CRLF
CRLF
starttls
receive "GET"
"HTTP/1.1 200 OK"CRLF
"Content-Length: 3"CRLF
CRLF
"abc"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ($server->{addr}),
         port => $server->{port});
    my $proxy = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    my $connect = Web::Transport::H1CONNECTTransport->new
        (http => $proxy, target => 'hoge.test');
    my $tls = Web::Transport::TLSTransport->new
        (transport => $connect,
         sni_host_name => Web::Host->parse_string ('hoge.test'),
         si_host_name => Web::Host->parse_string (Test::Certificates->cert_name),
         ca_file => Test::Certificates->ca_path ('cert.pem'));
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tls);
    my $d = '';
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'GET',
                                           target => '/test'}, cb => sub {
        my ($http, $type, $data) = @_;
        if ($type eq 'data') {
          $d .= $data;
        }
      });
    })->then (sub {
      test {
        is $d, 'abc';
      } $c;
      return $http->close;
    })->catch (sub {
      my $error = $_[0];
      test {
        is defined $error ? $error : '(undef)', undef;
      } $c;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'CONNECT https';

test {
  my $c = shift;
  {
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ('127.0.53.53'), port => int rand);
    my $proxy = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    my $connect = Web::Transport::H1CONNECTTransport->new
        (http => $proxy, target => 'hoge.test');
    my $tls = Web::Transport::TLSTransport->new
        (transport => $connect,
         sni_host_name => Web::Host->parse_string ('hoge.test'),
         si_host_name => Web::Host->parse_string (Test::Certificates->cert_name),
         ca_file => Test::Certificates->ca_path ('cert.pem'));
    my $http = Web::Transport::HTTPClientConnection->new (transport => $tls);
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'GET',
                                           target => '/test'}, cb => sub { });
    })->then (sub { test { ok 0 } $c }, sub {
      test {
        ok 1;
      } $c;
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  }
} n => 1, name => 'CONNECT https bad TCP host';

test {
  my $c = shift;
  {
    my $tcp = Web::Transport::TCPTransport->new
        (host => Web::Host->parse_string ('127.0.53.53'), port => int rand);
    my $proxy = Web::Transport::HTTPClientConnection->new (transport => $tcp);
    my $connect = Web::Transport::H1CONNECTTransport->new
        (http => $proxy, target => 'hoge.test');
    my $http = Web::Transport::HTTPClientConnection->new (transport => $connect);
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'GET',
                                           target => '/test'}, cb => sub { });
    })->then (sub { test { ok 0 } $c }, sub {
      test {
        ok 1;
      } $c;
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  }
} n => 1, name => 'CONNECT http bad TCP host';

test {
  my $c = shift;
  unix_server_as_cv (q{
receive "GET"
"HTTP/1.1 200 OK"CRLF
"Content-Length: 3"CRLF
CRLF
"xyz"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $unix = Web::Transport::UNIXDomainSocketTransport->new
        (path => $server->{port});
    my $http = Web::Transport::HTTPClientConnection->new (transport => $unix);
    my $d = '';
    $http->connect->then (sub {
      return $http->send_request_headers ({method => 'GET', target => '/'}, cb => sub {
        my ($http, $type, $data) = @_;
        if ($type eq 'data') {
          $d .= $data;
        }
      });
    })->then (sub {
      test {
        is $d, 'xyz';
      } $c;
      return $http->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'UNIX domain socket';

Test::Certificates->wait_create_cert;
run_tests;

=head1 LICENSE

Copyright 2016 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
