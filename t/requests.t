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
      $error = $data if $type eq 'responseerror';
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
      $error = $data if $type eq 'responseerror';
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
      $error = $data if $type eq 'responseerror';
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
      $error = $data if $type eq 'responseerror';
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

run_tests;
