use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->child ('t_deps/lib');
use lib glob path (__FILE__)->parent->parent->child ('t_deps/modules/*/lib');
use Test::More;
use Test::X1;
use Test::Certificates;
use Promise;
use AnyEvent::Util qw(run_cmd);
use Web::Transport::WSClient;
use Web::Host;
use Web::URL;

{
  package test::resolver1;
  sub resolve ($$) {
    my $host = $_[1]->stringify;
    warn "test::resolver1: Resolving |$host|...\n" if ($ENV{WEBUA_DEBUG} || 0) > 1;
    return Promise->resolve (Web::Host->parse_string ($_[0]->{$host}));
  }
}

{
  sub pp ($) {
    return bless $_[0], 'proxymanager';
  } # pp

  package proxymanager;
  use Promise;

  sub get_proxies_for_url ($$) {
    for (@{$_[0]}) {
      if (defined $_->{host} and not ref $_->{host}) {
        $_->{host} = Web::Host->parse_string ($_->{host});
      }
    }
    return Promise->resolve ($_[0]);
  } # get_proxies_for_url
}

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

Test::Certificates->generate_ca_cert;

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

sub server_as_cv ($) {
  return _server_as_cv ('localhost', '127.0.0.1', find_listenable_port, $_[0]);
} # server_as_cv

test {
  my $c = shift;
  my $url = Web::URL->parse_string (qq{ws://notfound.test/});
  my $invoked = 0;
  Web::Transport::WSClient->new (url => $url, cb => sub {
    $invoked++;
  }, resolver => (bless {}, 'test::resolver1'))->then (sub {
    my ($res) = $_[0];
    test {
      is $invoked, 0;
      ok $res->is_network_error;
      is $res->status, 0;
      is $res->status_text, '';
      is $res->ws_code, 1006;
      is $res->ws_reason, '';
      is ''.$res, "Network error: Can't resolve host |notfound.test|";
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 7, name => 'Bad host';

test {
  my $c = shift;
  my $url = Web::URL->parse_string (qq{about:blank});
  my $invoked = 0;
  Web::Transport::WSClient->new (url => $url, cb => sub {
    $invoked++;
  }, resolver => (bless {}, 'test::resolver1'))->then (sub {
    test { ok 0 } $c;
  }, sub {
    my ($res) = $_[0];
    test {
      is $invoked, 0;
      ok $res->is_network_error;
      is $res->status, 0;
      is $res->status_text, '';
      is $res->ws_code, 1006;
      is $res->ws_reason, '';
      is ''.$res, "Network error: Bad URL scheme |about|";
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 7, name => 'Bad URL scheme';

test {
  my $c = shift;
  my $url = Web::URL->parse_string (qq{https://bad.test/hoge});
  my $invoked = 0;
  Web::Transport::WSClient->new (url => $url, cb => sub {
    $invoked++;
  }, resolver => (bless {}, 'test::resolver1'))->then (sub {
    test { ok 0 } $c;
  }, sub {
    my ($res) = $_[0];
    test {
      is $invoked, 0;
      ok $res->is_network_error;
      is $res->status, 0;
      is $res->status_text, '';
      is $res->ws_code, 1006;
      is $res->ws_reason, '';
      is ''.$res, "Network error: Bad URL scheme |https|";
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 7, name => 'Bad URL scheme';

test {
  my $c = shift;
  my $url = Web::URL->parse_string (qq{ws://notfound.test/});
  my $invoked = 0;
  Web::Transport::WSClient->new (url => $url, cb => sub {
    $invoked++;
  }, method => 'POST')->then (sub {
    test { ok 0 } $c;
  }, sub {
    my ($res) = $_[0];
    test {
      is $invoked, 0;
      ok $res->is_network_error;
      is $res->status, 0;
      is $res->status_text, '';
      is $res->ws_code, 1006;
      is $res->ws_reason, '';
      is ''.$res, "Network error: Bad |method| argument |POST|";
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 7, name => 'Bad method';

test {
  my $c = shift;
  my $url = Web::URL->parse_string (qq{ws://notfound.test/});
  my $invoked = 0;
  Web::Transport::WSClient->new (url => $url, cb => sub {
    $invoked++;
  }, body => "abc")->then (sub {
    test { ok 0 } $c;
  }, sub {
    my ($res) = $_[0];
    test {
      is $invoked, 0;
      ok $res->is_network_error;
      is $res->status, 0;
      is $res->status_text, '';
      is $res->ws_code, 1006;
      is $res->ws_reason, '';
      is ''.$res, "Network error: Request body not allowed";
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 7, name => 'Bad request-body';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET"
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{ws://$server->{host}:$server->{port}/});
    my $invoked = 0;
    Web::Transport::WSClient->new (url => $url, cb => sub {
      $invoked++;
    })->then (sub {
      my ($res) = $_[0];
      test {
        is $invoked, 0;
        ok $res->is_network_error;
        is $res->status, 0;
        is $res->status_text, '';
        is $res->ws_code, 1006;
        is $res->ws_reason, '';
        is ''.$res, 'Network error: Connection closed without response';
      } $c;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 7, name => 'empty response';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET"
    "HTTP/1.1 201 OK ?"CRLF
    "Content-Length: 4"CRLF
    CRLF
    "hoge"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{ws://$server->{host}:$server->{port}/});
    my $invoked = 0;
    Web::Transport::WSClient->new (url => $url, cb => sub {
      $invoked++;
    })->then (sub {
      my ($res) = $_[0];
      test {
        is $invoked, 0;
        ok ! $res->is_network_error;
        is $res->status, 201;
        is $res->status_text, 'OK ?';
        is $res->ws_code, 1006;
        is $res->ws_reason, '';
        is ''.$res, 'WS handshake error: 201 OK ?';
        ok ! $res->ws_closed_cleanly;
      } $c;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 8, name => 'non-101 response';

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
    ws-send-header opcode=1 length=3
    "xyz"
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{ws://$server->{host}:$server->{port}/});
    my @data;
    Web::Transport::WSClient->new (url => $url, cb => sub {
      my ($client, $data, $is_text) = @_;
      if (@data and defined $data[-1] and defined $data) {
        $data[-1] .= $data;
      } else {
        push @data, $data;
      }
      return $client->close if not defined $data;
    })->then (sub {
      my ($res) = $_[0];
      test {
        is 0+@data, 2;
        is $data[0], 'xyz';
        is $data[1], undef;
        ok ! $res->is_network_error;
        is $res->status, 1006;
        is $res->status_text, '';
        is $res->ws_code, 1006;
        is $res->ws_reason, '';
        is ''.$res, 'WS closed (1006 || failed = 1, cleanly = 0)';
      } $c;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 9, name => 'force-closed by server';

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
    ws-receive-data, capture
    ws-send-header opcode=2 length=3
    sendcaptured
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{ws://$server->{host}:$server->{port}/});
    my @data;
    Web::Transport::WSClient->new (url => $url, cb => sub {
      my ($client, $data, $is_text) = @_;
      if (not defined $is_text) {
        return $client->send_binary ("\x80a\xA1");
      } else {
        if (@data and defined $data[-1] and defined $data) {
          $data[-1] .= $data;
        } else {
          push @data, $data;
        }
        return $client->close if not defined $data;
      }
    })->then (sub {
      my ($res) = $_[0];
      test {
        is 0+@data, 2;
        is $data[0], "\x80a\xA1";
        is $data[1], undef;
        ok ! $res->is_network_error;
        is $res->status, 1006;
        is $res->status_text, '';
        is $res->ws_code, 1006;
        is $res->ws_reason, '';
        ok ! $res->ws_closed_cleanly;
        is ''.$res, 'WS closed (1006 || failed = 1, cleanly = 0)';
      } $c;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 10, name => 'replied by server';

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
    ws-receive-data, capture
    ws-send-header opcode=2 length=captured
    sendcaptured
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{ws://$server->{host}:$server->{port}/});
    my @data;
    Web::Transport::WSClient->new (url => $url, cb => sub {
      my ($client, $data, $is_text) = @_;
      if (not defined $is_text) {
        return $client->send_text ("\x80a\xA1");
      } else {
        if (@data and defined $data[-1] and defined $data) {
          $data[-1] .= $data;
        } else {
          push @data, $data;
        }
        return $client->close if not defined $data;
      }
    })->then (sub {
      my ($res) = $_[0];
      test {
        is 0+@data, 2;
        is $data[0], "\xC2\x80a\xC2\xA1";
        is $data[1], undef;
        ok ! $res->is_network_error;
        is $res->status, 1006;
        is $res->status_text, '';
        is $res->ws_code, 1006;
        is $res->ws_reason, '';
        is ''.$res, 'WS closed (1006 || failed = 1, cleanly = 0)';
      } $c;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 9, name => 'replied by server - send_text';

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
    ws-receive-data, capture
    ws-send-header opcode=1 length=3
    sendcaptured
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{ws://$server->{host}:$server->{port}/});
    my @data;
    Web::Transport::WSClient->new (url => $url, cb => sub {
      my ($client, $data, $is_text) = @_;
      if (not defined $is_text) {
        return $client->send_binary ("\x80a\xA1");
      } else {
        if (@data and defined $data[-1] and defined $data) {
          $data[-1] .= $data;
        } else {
          push @data, $data;
        }
        return $client->close if not defined $data;
      }
    })->then (sub {
      my ($res) = $_[0];
      test {
        is 0+@data, 0;
        ok ! $res->is_network_error;
        is $res->status, 1002;
        is $res->status_text, 'Invalid UTF-8 in text frame';
        is $res->ws_code, 1002;
        is $res->ws_reason, 'Invalid UTF-8 in text frame';
        is ''.$res, 'WS closed (1002 |Invalid UTF-8 in text frame| failed = 1, cleanly = 0)';
      } $c;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 7, name => 'replied by server but invalid';

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
    ws-receive-data, capture
    ws-send-header opcode=2 length=3
    sendcaptured
    ws-receive-header
    ws-receive-data
    ws-send-header opcode=8 length=0
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{ws://$server->{host}:$server->{port}/});
    my @data;
    Web::Transport::WSClient->new (url => $url, cb => sub {
      my ($client, $data, $is_text) = @_;
      if (not defined $is_text) {
        return $client->send_binary ("\x80a\xA1");
      } else {
        if (@data and defined $data[-1] and defined $data) {
          $data[-1] .= $data;
        } else {
          push @data, $data;
        }
        return $client->close if not defined $data;
      }
    })->then (sub {
      my ($res) = $_[0];
      test {
        is 0+@data, 2;
        is $data[0], "\x80a\xA1";
        is $data[1], undef;
        ok ! $res->is_network_error;
        is $res->status, 1005;
        is $res->status_text, '';
        is $res->ws_code, 1005;
        is $res->ws_reason, '';
        is ''.$res, 'WS closed (1005 || failed = 0, cleanly = 1)';
      } $c;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 9, name => 'replied by server';

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
    my $url = Web::URL->parse_string (qq{ws://$server->{host}:$server->{port}/});
    my @data;
    Web::Transport::WSClient->new (url => $url, cb => sub {
      my ($client, $data, $is_text) = @_;
      if (not defined $is_text) {
        $client->send_binary ("\x80a\xA1\x{100}");
        $client->send_binary ("abc");
      } else {
        if (@data and defined $data[-1] and defined $data) {
          $data[-1] .= $data;
        } else {
          push @data, $data;
        }
        return $client->close if not defined $data;
      }
    })->then (sub {
      my ($res) = $_[0];
      test {
        is 0+@data, 0;
        ok ! $res->is_network_error;
        is $res->status, 1006;
        is $res->status_text, '';
        is $res->ws_code, 1006;
        is $res->ws_reason, '';
        ok ! $res->ws_closed_cleanly;
        is ''.$res, 'WS closed (1006 || failed = 1, cleanly = 0)';
      } $c;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 8, name => 'send_binary utf8-flagged';

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
    ws-send-header opcode=2 length=captured
    sendcaptured
    ws-receive-header
    ws-receive-data
    ws-send-header opcode=8 length=0
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{ws://$server->{host}:$server->{port}/abc/def});
    my @data;
    Web::Transport::WSClient->new (url => $url, params => {
      hoge => 'abc',
    }, cb => sub {
      my ($client, $data, $is_text) = @_;
      if (defined $is_text) {
        if (@data and defined $data[-1] and defined $data) {
          $data[-1] .= $data;
        } else {
          push @data, $data;
        }
        return $client->close if not defined $data;
      }
    })->then (sub {
      my ($res) = $_[0];
      test {
        is 0+@data, 2;
        like $data[0], qr{^GET /abc/def\?hoge=abc HTTP/1.1};
        is $data[1], undef;
        ok ! $res->is_network_error;
        is $res->status, 1005;
        is $res->status_text, '';
        is $res->ws_code, 1005;
        is $res->ws_reason, '';
        ok $res->ws_closed_cleanly;
        is ''.$res, 'WS closed (1005 || failed = 0, cleanly = 1)';
      } $c;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 10, name => 'params';

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
    ws-send-header opcode=2 length=captured
    sendcaptured
    ws-receive-header
    ws-receive-data
    ws-send-header opcode=8 length=0
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{ws://$server->{host}:$server->{port}/abc/def});
    my @data;
    Web::Transport::WSClient->new (url => $url, basic_auth => [
      hoge => 'abc',
    ], cb => sub {
      my ($client, $data, $is_text) = @_;
      if (defined $is_text) {
        if (@data and defined $data[-1] and defined $data) {
          $data[-1] .= $data;
        } else {
          push @data, $data;
        }
        return $client->close if not defined $data;
      }
    })->then (sub {
      my ($res) = $_[0];
      test {
        is 0+@data, 2;
        like $data[0], qr{^Authorization: Basic aG9nZTphYmM=\x0D$}m;
        is $data[1], undef;
        ok ! $res->is_network_error;
        is $res->status, 1005;
        is $res->status_text, '';
        is $res->ws_code, 1005;
        is $res->ws_reason, '';
        is ''.$res, 'WS closed (1005 || failed = 0, cleanly = 1)';
      } $c;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 9, name => 'basic auth';

test {
  my $c = shift;
  server_as_cv (q{
    starttls host=host2.test
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
    ws-receive-data, capture
    ws-send-header opcode=2 length=3
    sendcaptured
    ws-receive-header
    ws-receive-data
    ws-send-header opcode=8 length=0
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{wss://host2.test:$server->{port}/});
    my @data;
    Web::Transport::WSClient->new (url => $url,
    resolver => (bless {'host2.test' => '127.0.0.1'}, 'test::resolver1'),
    tls_options => {ca_file => Test::Certificates->ca_path ('cert.pem')},
    cb => sub {
      my ($client, $data, $is_text) = @_;
      if (not defined $is_text) {
        return $client->send_binary ("\x80a\xA1");
      } else {
        if (@data and defined $data[-1] and defined $data) {
          $data[-1] .= $data;
        } else {
          push @data, $data;
        }
        return $client->close if not defined $data;
      }
    })->then (sub {
      my ($res) = $_[0];
      test {
        is 0+@data, 2;
        is $data[0], "\x80a\xA1";
        is $data[1], undef;
        ok ! $res->is_network_error;
        is $res->status, 1005;
        is $res->status_text, '';
        is $res->ws_code, 1005;
        is $res->ws_reason, '';
        is ''.$res, 'WS closed (1005 || failed = 0, cleanly = 1)';
      } $c;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 9, name => 'https - replied by server';

test {
  my $c = shift;
  server_as_cv (q{
    receive "CONNECT"
    receive CRLFCRLF, end capture
    "HTTP/1.1 200 OK"CRLF
    CRLF
    starttls host=host2.test
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
    ws-receive-data, capture
    ws-send-header opcode=2 length=3
    sendcaptured
    ws-receive-header
    ws-receive-data
    ws-send-header opcode=8 length=0
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{wss://host2.test});
    my @data;
    Web::Transport::WSClient->new (url => $url,
    tls_options => {ca_file => Test::Certificates->ca_path ('cert.pem')},
    proxy_manager => pp [{protocol => 'http', host => $server->{host},
                          port => $server->{port}}],
    cb => sub {
      my ($client, $data, $is_text) = @_;
      if (not defined $is_text) {
        return $client->send_binary ("\x80a\xA1");
      } else {
        if (@data and defined $data[-1] and defined $data) {
          $data[-1] .= $data;
        } else {
          push @data, $data;
        }
        return $client->close if not defined $data;
      }
    })->then (sub {
      my ($res) = $_[0];
      test {
        is 0+@data, 2;
        is $data[0], "\x80a\xA1";
        is $data[1], undef;
        ok ! $res->is_network_error;
        is $res->status, 1005;
        is $res->status_text, '';
        is $res->ws_code, 1005;
        is $res->ws_reason, '';
        is ''.$res, 'WS closed (1005 || failed = 0, cleanly = 1)';
      } $c;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 9, name => 'proxy - https - replied by server';

test {
  my $c = shift;
  my $invoked = 0;
  Web::Transport::WSClient->new (cb => sub {
    $invoked++;
  }, resolver => (bless {}, 'test::resolver1'))->then (sub {
    test { ok 0 } $c;
  }, sub {
    my ($res) = $_[0];
    test {
      is $invoked, 0;
      ok $res->is_network_error;
      is $res->status, 0;
      is $res->status_text, '';
      is $res->ws_code, 1006;
      is $res->ws_reason, '';
      is ''.$res, "Network error: No |url| argument";
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 7, name => 'No URL';

test {
  my $c = shift;
  my $invoked = 0;
  Web::Transport::WSClient->new (path => ['hoge', 'fuga'], cb => sub {
    $invoked++;
  }, resolver => (bless {}, 'test::resolver1'))->then (sub {
    test { ok 0 } $c;
  }, sub {
    my ($res) = $_[0];
    test {
      is $invoked, 0;
      ok $res->is_network_error;
      is $res->status, 0;
      is $res->status_text, '';
      is $res->ws_code, 1006;
      is $res->ws_reason, '';
      is ''.$res, "Network error: No |url| argument";
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 7, name => 'No URL';

Test::Certificates->wait_create_cert;
run_tests;

=head1 LICENSE

Copyright 2016 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
