use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->child ('t_deps/modules/*/lib');
use Test::More;
use Test::X1;
use Test::HTCT::Parser;
use HTTP;
use Promise;
use AnyEvent::Util qw(run_cmd);

my $server_pids = {};
END { kill 'KILL', $_ for keys %$server_pids }
sub server_as_cv ($) {
  my $code = $_[0];
  my $cv = AE::cv;
  my $started;
  my $pid;
  my $data = '';
  my $port = int (rand 10000) + 1024;
  run_cmd
      ['perl', path (__FILE__)->parent->parent->child ('t_deps/server.pl'), '127.0.0.1', $port],
      '<' => \$code,
      '>' => sub {
        $data .= $_[0] if defined $_[0];
        return if $started;
        if ($data =~ /^\[server (.+) ([0-9]+)\]/m) {
          $cv->send ({pid => $pid, host => $1, port => $2,
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
} # server_as_cv

test {
  my $c = shift;
  my $http = HTTP->new_from_host_and_port ('localhost', rand);
  my $p = $http->send_request ({method => 'GET', target => '/'});
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
    my $http = HTTP->new_from_host_and_port ($server->{host}, $server->{port});
    $http->connect->then (sub {
      return $http->send_request ({method => 'GET', target => '/'});
    })->then (sub {
      my $p = $http->send_request ({method => 'GET', target => '/'});
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
    my $http = HTTP->new_from_host_and_port ($server->{host}, $server->{port});
    $http->connect->then (sub {
      my $p1 = $http->send_request ({method => 'GET', target => '/'});
      my $p = $http->send_request ({method => 'GET', target => '/'});
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
    my $http = HTTP->new_from_host_and_port ($server->{host}, $server->{port});
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
          $http->send_request
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
} n => 7, name => 'send_request with bad headers';

test {
  my $c = shift;
  server_as_cv (q{
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $http = HTTP->new_from_host_and_port ($server->{host}, $server->{port});
    my $error;
    $http->onevent (sub {
      my ($http, $req, $type, $data) = @_;
      $error = $data if $type eq 'complete';
    });
    $http->connect->then (sub {
      return $http->send_request ({method => 'GET', target => '/'});
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
    my $http = HTTP->new_from_host_and_port ($server->{host}, $server->{port});
    my $error;
    $http->onevent (sub {
      my ($http, $req, $type, $data) = @_;
      $error = $data if $type eq 'complete';
    });
    $http->connect->then (sub {
      return $http->send_request ({method => 'GET', target => '/'});
    })->then (sub {
      return $http->send_request ({method => 'GET', target => '/'});
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
    my $http = HTTP->new_from_host_and_port ($server->{host}, $server->{port});
    my $error;
    $http->onevent (sub {
      my ($http, $req, $type, $data) = @_;
      $error = $data->{reason} if $type eq 'complete';
    });
    $http->connect->then (sub {
      return $http->send_ws_message ('text', 'abc');
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
} n => 1, name => 'send_ws_message before request';

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
    my $http = HTTP->new_from_host_and_port ($server->{host}, $server->{port});
    my $error;
    $http->onevent (sub {
      my ($http, $req, $type, $data) = @_;
      $error = $data->{reason} if $type eq 'complete';
    });
    $http->connect->then (sub {
      return $http->send_request ({method => 'GET', target => '/'}, ws => 1);
    })->then (sub {
      return $http->send_ws_message ('text', 'abc');
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
} n => 1, name => 'send_ws_message after bad handshake';

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
    my $http = HTTP->new_from_host_and_port ($server->{host}, $server->{port});
    my $sent = 0;
    $http->onevent (sub {
      my ($http, $req, $type, $data) = @_;
      if ($type eq 'headers') {
        $http->send_ws_message ('text', 'abc');
        $sent++;
      }
    });
    $http->connect->then (sub {
      return $http->send_request ({method => 'GET', target => '/'}, ws => 1);
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
} n => 1, name => 'send_ws_message ok';

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
    my $http = HTTP->new_from_host_and_port ($server->{host}, $server->{port});
    my $error = 0;
    $http->onevent (sub {
      my ($http, $req, $type, $data) = @_;
      if ($type eq 'headers') {
        eval {
          $http->send_ws_message ('text?', 'abc');
        } or do {
          test {
            like $@, qr{^Unknown type};
          } $c;
          $error++;
        }
      }
    });
    $http->connect->then (sub {
      return $http->send_request ({method => 'GET', target => '/'}, ws => 1);
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
} n => 2, name => 'send_ws_message unknown type';

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
    my $http = HTTP->new_from_host_and_port ($server->{host}, $server->{port});
    my $error = 0;
    $http->onevent (sub {
      my ($http, $req, $type, $data) = @_;
      if ($type eq 'headers') {
        eval {
          $http->send_ws_message ('text', 'a' x (2**31));
        } or do {
          test {
            like $@, qr{^Data too large};
          } $c;
          $error++;
        }
      }
    });
    $http->connect->then (sub {
      return $http->send_request ({method => 'GET', target => '/'}, ws => 1);
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
} n => 2, name => 'send_ws_message data too large';

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
    my $http = HTTP->new_from_host_and_port ($server->{host}, $server->{port});
    my $error = 0;
    $http->onevent (sub {
      my ($http, $req, $type, $data) = @_;
      if ($type eq 'headers') {
        eval {
          $http->send_ws_message ('text', "\x{100}");
        } or do {
          test {
            like $@, qr{^Data is utf8-flagged};
          } $c;
          $error++;
        }
      }
    });
    $http->connect->then (sub {
      return $http->send_request ({method => 'GET', target => '/'}, ws => 1);
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
} n => 2, name => 'send_ws_message data utf8 flagged';

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
    my $http = HTTP->new_from_host_and_port ($server->{host}, $server->{port});
    my $sent = 0;
    $http->onevent (sub {
      my ($http, $req, $type, $data) = @_;
      if ($type eq 'headers') {
        $http->close;
        $sent++;
      }
    });
    $http->connect->then (sub {
      return $http->send_request ({method => 'GET', target => '/'}, ws => 1);
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
    my $http = HTTP->new_from_host_and_port ($server->{host}, $server->{port});
    my $sent = 0;
    $http->onevent (sub {
      my ($http, $req, $type, $data) = @_;
      if ($type eq 'headers') {
        $http->close (status => 1234);
        $sent++;
      }
    });
    $http->connect->then (sub {
      return $http->send_request ({method => 'GET', target => '/'}, ws => 1);
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
    my $http = HTTP->new_from_host_and_port ($server->{host}, $server->{port});
    my $sent = 0;
    $http->onevent (sub {
      my ($http, $req, $type, $data) = @_;
      if ($type eq 'headers') {
        $http->close (status => 1234, reason => 'av c');
        $sent++;
      }
    });
    $http->connect->then (sub {
      return $http->send_request ({method => 'GET', target => '/'}, ws => 1);
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
    my $http = HTTP->new_from_host_and_port ($server->{host}, $server->{port});
    my $sent = 0;
    $http->onevent (sub {
      my ($http, $req, $type, $data) = @_;
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
    $http->connect->then (sub {
      return $http->send_request ({method => 'GET', target => '/'}, ws => 1);
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
    my $http = HTTP->new_from_host_and_port ($server->{host}, $server->{port});
    my $sent = 0;
    $http->onevent (sub {
      my ($http, $req, $type, $data) = @_;
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
    $http->connect->then (sub {
      return $http->send_request ({method => 'GET', target => '/'}, ws => 1);
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
    my $http = HTTP->new_from_host_and_port ($server->{host}, $server->{port});
    my $sent = 0;
    $http->onevent (sub {
      my ($http, $req, $type, $data) = @_;
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
    $http->connect->then (sub {
      return $http->send_request ({method => 'GET', target => '/'}, ws => 1);
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
    my $http = HTTP->new_from_host_and_port ($server->{host}, $server->{port});
    my $sent = 0;
    $http->onevent (sub {
      my ($http, $req, $type, $data) = @_;
      if ($type eq 'headers') {
        AE::postpone {
          $http->abort;
          $sent++;
        };
      }
    });
    $http->connect->then (sub {
      return $http->send_request ({method => 'GET', target => '/'});
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
    my $http = HTTP->new_from_host_and_port ($server->{host}, $server->{port});
    my $sent = 0;
    $http->onevent (sub {
      my ($http, $req, $type, $data) = @_;
      if ($type eq 'headers') {
        AE::postpone {
          $http->abort;
          $sent++;
        };
      }
    });
    $http->connect->then (sub {
      return $http->send_request ({method => 'GET', target => '/'}, ws => 1);
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
    my $http = HTTP->new_from_host_and_port ($server->{host}, $server->{port});
    my $sent = 0;
    my $pong = 0;
    $http->onevent (sub {
      my ($http, $req, $type, $data) = @_;
      if ($type eq 'headers') {
        $http->send_ping;
        $sent++;
      } elsif ($type eq 'ping') {
        $pong++;
      }
    });
    $http->connect->then (sub {
      return $http->send_request ({method => 'GET', target => '/'}, ws => 1);
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
    my $http = HTTP->new_from_host_and_port ($server->{host}, $server->{port});
    my $sent = 0;
    $http->onevent (sub {
      my ($http, $req, $type, $data) = @_;
      if ($type eq 'headers') {
        $http->send_ping (pong => 1);
        $sent++;
      }
    });
    $http->connect->then (sub {
      return $http->send_request ({method => 'GET', target => '/'}, ws => 1);
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
    my $http = HTTP->new_from_host_and_port ($server->{host}, $server->{port});
    my $sent = 0;
    $http->onevent (sub {
      my ($http, $req, $type, $data) = @_;
      if ($type eq 'headers') {
        $http->send_ping (data => "ab c");
        $sent++;
      }
    });
    $http->connect->then (sub {
      return $http->send_request ({method => 'GET', target => '/'}, ws => 1);
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
    my $http = HTTP->new_from_host_and_port ($server->{host}, $server->{port});
    my $error = 0;
    $http->onevent (sub {
      my ($http, $req, $type, $data) = @_;
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
    $http->connect->then (sub {
      return $http->send_request ({method => 'GET', target => '/'}, ws => 1);
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
    my $http = HTTP->new_from_host_and_port ($server->{host}, $server->{port});
    my $error = 0;
    $http->onevent (sub {
      my ($http, $req, $type, $data) = @_;
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
    $http->connect->then (sub {
      return $http->send_request ({method => 'GET', target => '/'}, ws => 1);
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
    my $http = HTTP->new_from_host_and_port ($server->{host}, $server->{port});
    my $error = 0;
    $http->onevent (sub {
      my ($http, $req, $type, $data) = @_;
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
    $http->connect->then (sub {
      return $http->send_request ({method => 'GET', target => '/'}, ws => 1);
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
    my $http = HTTP->new_from_host_and_port ($server->{host}, $server->{port});
    my $ping = 0;
    $http->onevent (sub {
      my ($http, $req, $type, $data) = @_;
      if ($type eq 'headers') {
        $http->close;
      } elsif ($type eq 'ping') {
        $ping++;
      }
    });
    $http->connect->then (sub {
      return $http->send_request ({method => 'GET', target => '/'}, ws => 1);
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
    my $http = HTTP->new_from_host_and_port ($server->{host}, $server->{port});
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
    my $http = HTTP->new_from_host_and_port ($server->{host}, $server->{port});
    my $sent = 0;
    my $received = '';
    my @ev;
    $http->onevent (sub {
      my ($http, $req, $type, $data) = @_;
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
    $http->connect->then (sub {
      return $http->send_request ({method => 'CONNECT', target => 'test'});
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
    my $http = HTTP->new_from_host_and_port ($server->{host}, $server->{port});
    my $sent = 0;
    my $received = '';
    my @ev;
    $http->onevent (sub {
      my ($http, $req, $type, $data) = @_;
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
    $http->connect->then (sub {
      return $http->send_request ({method => 'CONNECT', target => 'test'});
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
    my $http = HTTP->new_from_host_and_port ($server->{host}, $server->{port});
    my $sent = 0;
    my $received = '';
    my @ev;
    $http->onevent (sub {
      my ($http, $req, $type, $data) = @_;
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
    $http->connect->then (sub {
      return $http->send_request ({method => 'CONNECT', target => 'test'});
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
    my $http = HTTP->new_from_host_and_port ($server->{host}, $server->{port});
    my $error = 0;
    my $x;
    my $p = Promise->new (sub { $x = $_[0] });
    $http->onevent (sub {
      my ($http, $req, $type, $data) = @_;
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
    $http->connect->then (sub {
      return $http->send_request ({method => 'CONNECT', target => 'test'});
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
    my $http = HTTP->new_from_host_and_port ($server->{host}, $server->{port});
    my $received = '';
    $http->onevent (sub {
      my ($http, $req, $type, $data) = @_;
      if ($type eq 'headers') {
        $received .= '(headers)';
        AE::postpone {
          $http->close;
        };
      } elsif ($type eq 'data') {
        $received .= $data;
      }
    });
    $http->connect->then (sub {
      return $http->send_request ({method => 'CONNECT', target => 'test'});
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
    my $http = HTTP->new_from_host_and_port ($server->{host}, $server->{port});
    $http->onevent (sub {
      my ($http, $req, $type, $data) = @_;
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
    $http->connect->then (sub {
      return $http->send_request ({method => 'CONNECT', target => 'test'});
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
    my $http = HTTP->new_from_host_and_port ($server->{host}, $server->{port});
    $http->onevent (sub {
      my ($http, $req, $type, $data) = @_;
      if ($type eq 'data') {
        test {
          is $data, 'OK';
        } $c;
      }
    });
    $http->connect->then (sub {
      my $p = $http->send_request ({method => 'GET', target => 'test',
                                    headers => [['Content-Length' => 4]]});
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
    my $http = HTTP->new_from_host_and_port ($server->{host}, $server->{port});
    $http->onevent (sub {
      my ($http, $req, $type, $data) = @_;
      if ($type eq 'data') {
        test {
          ok 0;
        } $c;
      }
    });
    $http->connect->then (sub {
      my $p = $http->send_request ({method => 'GET', target => 'test',
                                    headers => [['Content-Length' => 4]]});
      test {
        eval {
          $http->send_data (\"hoge!");
        } or do {
          like $@, qr/^Data too long/;
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
} n => 1, name => 'with request body - too long';

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
    my $http = HTTP->new_from_host_and_port ($server->{host}, $server->{port});
    $http->onevent (sub {
      my ($http, $req, $type, $data) = @_;
      if ($type eq 'data') {
        test {
          ok 0;
        } $c;
      }
    });
    $http->connect->then (sub {
      my $p = $http->send_request ({method => 'GET', target => 'test',
                                    headers => [['Content-Length' => 4]]});
      $http->send_data (\"ho");
      test {
        eval {
          $http->send_data (\"ge!");
        } or do {
          like $@, qr/^Data too long/;
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
} n => 1, name => 'with request body - too long';

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
    my $http = HTTP->new_from_host_and_port ($server->{host}, $server->{port});
    $http->onevent (sub {
      my ($http, $req, $type, $data) = @_;
      if ($type eq 'data') {
        test {
          ok 0;
        } $c;
      }
    });
    $http->connect->then (sub {
      my $p = $http->send_request ({method => 'GET', target => 'test',
                                    headers => [['Content-Length' => 0]]});
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
    my $http = HTTP->new_from_host_and_port ($server->{host}, $server->{port});
    $http->onevent (sub {
      my ($http, $req, $type, $data) = @_;
    });
    $http->connect->then (sub {
      my $p = $http->send_request ({method => 'GET', target => 'test',
                                    headers => [['Content-Length' => 4]]});
      return $http->close->catch (sub {
        my $err = $_[0];
        test {
          like $err, qr{^Request body is not sent};
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
    my $http = HTTP->new_from_host_and_port ($server->{host}, $server->{port});
    $http->onevent (sub {
      my ($http, $req, $type, $data) = @_;
      if ($type eq 'data') {
        test {
          ok 0;
        } $c;
      }
    });
    $http->connect->then (sub {
      my $p = $http->send_request ({method => 'GET', target => 'test',
                                    headers => [['Content-Length' => 4]]});
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

run_tests;
