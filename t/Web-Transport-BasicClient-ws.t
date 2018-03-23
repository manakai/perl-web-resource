use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->child ('t_deps/lib');
use lib glob path (__FILE__)->parent->parent->child ('t_deps/modules/*/lib');
use Test::More;
use Test::X1;
use Test::Certificates;
use Promise;
use Promised::Flow;
use AnyEvent::Util qw(run_cmd);
use Web::Transport::BasicClient;
use Web::Host;
use Web::URL;
use DataView;
use ArrayBuffer;

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

sub reading (&$) {
  my ($code, $readable) = @_;
  my $no_byob;
  my $reader = eval { $readable->get_reader ('byob') } || $readable->get_reader;
  my $read; $read = sub {
    return $reader->read (DataView->new (ArrayBuffer->new (100)))->then (sub {
      return if $_[0]->{done};
      $code->($_[0]->{value});
      return $read->();
    });
  }; # $read
  return promised_cleanup { undef $read } $read->();
} # reading

test {
  my $c = shift;
  my $url = Web::URL->parse_string (qq{ws://notfound.test/});
  my $client = Web::Transport::BasicClient->new_from_url ($url, {
    resolver => (bless {}, 'test::resolver1'),
  });
  $client->request (url => $url)->catch (sub {
    my $res = $_[0];
    test {
      ok $res->is_network_error;
      is $res->status, 0;
      is $res->status_text, '';
      is $res->ws_code, 1006;
      is $res->ws_reason, '';
      like ''.$res, qr{^\QNetwork error: Protocol error: Can't resolve host |notfound.test|\E};
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 6, name => 'Bad host';

test {
  my $c = shift;
  my $url = Web::URL->parse_string (qq{about:blank});
  eval { Web::Transport::BasicClient->new_from_url ($url) };
  is $@->name, 'TypeError';
  is $@->message, 'The URL does not have a tuple origin';
  is $@->file_name, __FILE__;
  is $@->line_number, __LINE__-4;
  done $c;
} n => 4, name => 'Bad URL scheme';

test {
  my $c = shift;
  server_as_cv (q{
    receive "HTTP"
    "HTTP/1.1 200 OK!"CRLF
    CRLF
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{ws://$server->{host}:$server->{port}/});
    my $client = Web::Transport::BasicClient->new_from_url ($url);
    $client->request (url => $url, method => 'POST')->catch (sub {
      my ($res) = $_[0];
      test {
        ok ! $res->is_network_error;
        is $res->status, 200;
        is $res->status_text, 'OK!';
        is $res->ws_code, 1006;
        is $res->ws_reason, '';
        is ''.$res, 'WS handshake error: 200 OK!';
      } $c;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 6, name => 'bad request method POST';

test {
  my $c = shift;
  server_as_cv (q{
    receive "HTTP"
    "HTTP/1.1 200 OK!"CRLF
    CRLF
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{ws://$server->{host}:$server->{port}/});
    my $client = Web::Transport::BasicClient->new_from_url ($url);
    $client->request (url => $url, body => "abcdefg")->catch (sub {
      my ($res) = $_[0];
      test {
        ok $res->is_network_error;
        is $res->network_error_message, 'Request body is not allowed';
        is $res->status, 0;
        is $res->status_text, '';
        is $res->ws_code, 1006;
        is $res->ws_reason, '';
        like ''.$res, qr{^Network error: TypeError: Request body is not allowed };
      } $c;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 7, name => 'bad request with request-body';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET"
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{ws://$server->{host}:$server->{port}/});
    my $client = Web::Transport::BasicClient->new_from_url ($url);
    $client->request (url => $url)->catch (sub {
      my ($res) = $_[0];
      test {
        ok $res->is_network_error;
        is $res->status, 0;
        is $res->status_text, '';
        is $res->ws_code, 1006;
        is $res->ws_reason, '';
        like ''.$res, qr{^Network error: HTTP parse error: Connection closed without response};
      } $c;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 6, name => 'empty response';

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
    my $client = Web::Transport::BasicClient->new_from_url ($url);
    $client->request (url => $url)->catch (sub {
      my ($res) = $_[0];
      test {
        ok ! $res->is_network_error;
        is $res->status, 201;
        is $res->status_text, 'OK ?';
        is $res->ws_code, 1006;
        is $res->ws_reason, '';
        like ''.$res, qr{^\QWS handshake error: 201 OK ?\E};
        ok ! $res->ws_closed_cleanly;
      } $c;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 7, name => 'non-101 response';

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
    my $client = Web::Transport::BasicClient->new_from_url ($url);
    my $res;
    $client->request (url => $url)->then (sub {
      $res = $_[0];
      test {
        ok ! $res->is_network_error;
        is $res->network_error_message, undef;
        is $res->status, 101;
        is $res->status_text, 'OK';
        ok ! $res->is_success;
        ok ! $res->is_error;
        is $res->status_line, '101 OK';
        isa_ok $res->ws_messages, 'ReadableStream';
        is $res->ws_code, 1006;
        is $res->ws_reason, '';
        ok ! $res->ws_closed_cleanly;
        is $res->header ('Connection'), 'Upgrade';
        ok $res->header ('Sec-WebSocket-Accept');
        is $res->body_bytes, undef;
        ok ! $res->incomplete;
        is $res->stringify, 'Response: 101 OK';
      } $c, name => 'first result object';

      return reading {
        my $msg = $_[0];
        my $data = '';
        return Promise->resolve->then (sub {
          if (defined $msg->{text_body}) {
            return reading { $data .= ${$_[0]} } $msg->{text_body};
          } else {
            return reading { $data .= $_[0]->manakai_to_string } $msg->{body};
          }
        })->then (sub {
          if (@data and defined $data[-1]) {
            $data[-1] .= $data;
          } else {
            push @data, $data;
          }
        });
      } $res->ws_messages;
    })->then (sub {
      return $res->ws_close;
    })->then (sub {
      my $res2 = $_[0];
      test {
        is 0+@data, 1;
        is $data[0], 'xyz';
        ok ! $res2->is_network_error;
        is $res2->status, 1006;
        is $res2->status_text, '';
        is $res2->ws_code, 1006;
        is $res2->ws_reason, '';
        is ''.$res2, 'WS closed (1006 || failed = 1, cleanly = 0)';
      } $c;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 24, name => 'force-closed by server';

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
    my $res;
    my @data;
    my $client = Web::Transport::BasicClient->new_from_url ($url);
    $client->request (url => $url)->then (sub {
      $res = $_[0];
      $res->ws_send_binary ("\x80a\xA1");

      return reading {
        my $msg = $_[0];
        my $data = '';
        return Promise->resolve->then (sub {
          if (defined $msg->{text_body}) {
            return reading { $data .= ${$_[0]} } $msg->{text_body};
          } else {
            return reading { $data .= $_[0]->manakai_to_string } $msg->{body};
          }
        })->then (sub {
          if (@data and defined $data[-1]) {
            $data[-1] .= $data;
          } else {
            push @data, $data;
          }
        });
      } $res->ws_messages;
    })->then (sub {
      return $res->ws_close;
    })->then (sub {
      my $res2 = $_[0];
      test {
        is 0+@data, 1;
        is $data[0], "\x80a\xA1";
        ok ! $res2->is_network_error;
        is $res2->status, 1006;
        is $res2->status_text, '';
        is $res2->ws_code, 1006;
        is $res2->ws_reason, '';
        ok ! $res2->ws_closed_cleanly;
        is ''.$res2, 'WS closed (1006 || failed = 1, cleanly = 0)';
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
    ws-receive-header
    ws-receive-data, capture
    ws-send-header opcode=2 length=captured
    sendcaptured
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{ws://$server->{host}:$server->{port}/});
    my $res;
    my @data;
    my $client = Web::Transport::BasicClient->new_from_url ($url);
    $client->request (url => $url)->then (sub {
      $res = $_[0];
      $res->ws_send_text ("\x80a\xA1");

      return reading {
        my $msg = $_[0];
        my $data = '';
        return Promise->resolve->then (sub {
          if (defined $msg->{text_body}) {
            return reading { $data .= ${$_[0]} } $msg->{text_body};
          } else {
            return reading { $data .= $_[0]->manakai_to_string } $msg->{body};
          }
        })->then (sub {
          if (@data and defined $data[-1]) {
            $data[-1] .= $data;
          } else {
            push @data, $data;
          }
        });
      } $res->ws_messages;
    })->then (sub {
      return $res->ws_close;
    })->then (sub {
      my $res2 = $_[0];
      test {
        is 0+@data, 1;
        is $data[0], "\xC2\x80a\xC2\xA1";
        ok ! $res2->is_network_error;
        is $res2->status, 1006;
        is $res2->status_text, '';
        is $res2->ws_code, 1006;
        is $res2->ws_reason, '';
        is ''.$res2, 'WS closed (1006 || failed = 1, cleanly = 0)';
      } $c;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 8, name => 'replied by server - send_text';

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
    my $res;
    my @data;
    my $client = Web::Transport::BasicClient->new_from_url ($url);
    $client->request (url => $url)->then (sub {
      $res = $_[0];
      $res->ws_send_binary ("\x80a\xA1");

      return reading {
        my $msg = $_[0];
        my $data = '';
        return Promise->resolve->then (sub {
          if (defined $msg->{text_body}) {
            return reading { $data .= ${$_[0]} } $msg->{text_body};
          } else {
            return reading { $data .= $_[0]->manakai_to_string } $msg->{body};
          }
        })->then (sub {
          if (@data and defined $data[-1]) {
            $data[-1] .= $data;
          } else {
            push @data, $data;
          }
        });
      } $res->ws_messages;
    })->then (sub {
      return $res->ws_close;
    })->then (sub {
      my $res2 = $_[0];
      test {
        is 0+@data, 0;
        ok ! $res2->is_network_error;
        is $res2->status, 1002;
        is $res2->status_text, 'Invalid UTF-8 in text frame';
        is $res2->ws_code, 1002;
        is $res2->ws_reason, 'Invalid UTF-8 in text frame';
        is ''.$res2, 'WS closed (1002 |Invalid UTF-8 in text frame| failed = 1, cleanly = 0)';
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
    my $res;
    my @data;
    my $client = Web::Transport::BasicClient->new_from_url ($url);
    return $client->request (url => $url)->then (sub {
      $res = $_[0];
      $res->ws_send_binary ("\x80a\xA1");
      $res->ws_close;

      return reading {
        my $msg = $_[0];
        my $data = '';
        return Promise->resolve->then (sub {
          if (defined $msg->{text_body}) {
            return reading { $data .= ${$_[0]} } $msg->{text_body};
          } else {
            return reading { $data .= $_[0]->manakai_to_string } $msg->{body};
          }
        })->then (sub {
          if (@data and defined $data[-1]) {
            $data[-1] .= $data;
          } else {
            push @data, $data;
          }
        });
      } $res->ws_messages;
    })->then (sub {
      return $res->ws_close;
    })->then (sub {
      my $res2 = $_[0];
      test {
        is 0+@data, 1;
        is $data[0], "\x80a\xA1";
        ok ! $res2->is_network_error;
        is $res2->status, 1005;
        is $res2->status_text, '';
        is $res2->ws_code, 1005;
        is $res2->ws_reason, '';
        is ''.$res2, 'WS closed (1005 || failed = 0, cleanly = 1)';
      } $c;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 8, name => 'replied by server';

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
    my $res;
    my @data;
    my $client = Web::Transport::BasicClient->new_from_url ($url);
    $client->request (url => $url)->then (sub {
      $res = $_[0];
      $res->ws_send_binary ("\x80a\xA1\x{100}");
      $res->ws_send_binary ("abc");
      return $res->ws_close;
    })->then (sub {
      my $res2 = $_[0];
      test {
        is 0+@data, 0;
        ok $res2->is_network_error;
        is $res2->network_error_message, 'The argument is a utf8-flaged string';
        is $res2->status, 0;
        is $res2->status_text, '';
        is $res2->ws_code, 1006;
        is $res2->ws_reason, '';
        ok ! $res2->ws_closed_cleanly;
        like ''.$res2, qr{^Network error: TypeError: The argument is a utf8-flaged string at \Q@{[__FILE__]}\E line @{[__LINE__-14]}};
      } $c;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 9, name => 'send_binary utf8-flagged';

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
    my $res;
    my @data;
    my $client = Web::Transport::BasicClient->new_from_url ($url);
    $client->request (url => $url, params => {
      hoge => 'abc',
    })->then (sub {
      $res = $_[0];
      $res->ws_close;

      return reading {
        my $msg = $_[0];
        my $data = '';
        return Promise->resolve->then (sub {
          if (defined $msg->{text_body}) {
            return reading { $data .= ${$_[0]} } $msg->{text_body};
          } else {
            return reading { $data .= $_[0]->manakai_to_string } $msg->{body};
          }
        })->then (sub {
          if (@data and defined $data[-1]) {
            $data[-1] .= $data;
          } else {
            push @data, $data;
          }
        });
      } $res->ws_messages;
    })->then (sub {
      return $res->ws_close;
    })->then (sub {
      my $res2 = $_[0];
      test {
        is 0+@data, 1;
        like $data[0], qr{^GET /abc/def\?hoge=abc HTTP/1.1};
        ok ! $res2->is_network_error;
        is $res2->status, 1005;
        is $res2->status_text, '';
        is $res2->ws_code, 1005;
        is $res2->ws_reason, '';
        ok $res2->ws_closed_cleanly;
        is ''.$res2, 'WS closed (1005 || failed = 0, cleanly = 1)';
      } $c;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 9, name => 'params';

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
    my $res;
    my @data;
    my $client = Web::Transport::BasicClient->new_from_url ($url);
    $client->request (url => $url, basic_auth => [
      hoge => 'abc',
    ])->then (sub {
      $res = $_[0];
      $res->ws_close;

      return reading {
        my $msg = $_[0];
        my $data = '';
        return Promise->resolve->then (sub {
          if (defined $msg->{text_body}) {
            return reading { $data .= ${$_[0]} } $msg->{text_body};
          } else {
            return reading { $data .= $_[0]->manakai_to_string } $msg->{body};
          }
        })->then (sub {
          if (@data and defined $data[-1]) {
            $data[-1] .= $data;
          } else {
            push @data, $data;
          }
        });
      } $res->ws_messages;
    })->then (sub {
      return $res->ws_close;
    })->then (sub {
      my $res2 = $_[0];
      test {
        is 0+@data, 1;
        like $data[0], qr{^Authorization: Basic aG9nZTphYmM=\x0D$}m;
        ok ! $res2->is_network_error;
        is $res2->status, 1005;
        is $res2->status_text, '';
        is $res2->ws_code, 1005;
        is $res2->ws_reason, '';
        is ''.$res2, 'WS closed (1005 || failed = 0, cleanly = 1)';
      } $c;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 8, name => 'basic auth';

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
    my $res;
    my @data;
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      resolver => (bless {'host2.test' => '127.0.0.1'}, 'test::resolver1'),
      tls_options => ({ca_file => Test::Certificates->ca_path ('cert.pem')}),
    });
    $client->request (url => $url)->then (sub {
      $res = $_[0];
      $res->ws_send_binary ("\x80a\xA1");

      return reading {
        my $msg = $_[0];
        my $data = '';
        return Promise->resolve->then (sub {
          if (defined $msg->{text_body}) {
            return reading { $data .= ${$_[0]} } $msg->{text_body};
          } else {
            $res->ws_close;
            return reading { $data .= $_[0]->manakai_to_string } $msg->{body};
          }
        })->then (sub {
          if (@data and defined $data[-1]) {
            $data[-1] .= $data;
          } else {
            push @data, $data;
          }
        });
      } $res->ws_messages;
    })->then (sub {
      return $res->ws_close;
    })->then (sub {
      my ($res2) = $_[0];
      test {
        is 0+@data, 1;
        is $data[0], "\x80a\xA1";
        ok ! $res2->is_network_error;
        is $res2->status, 1005;
        is $res2->status_text, '';
        is $res2->ws_code, 1005;
        is $res2->ws_reason, '';
        is ''.$res2, 'WS closed (1005 || failed = 0, cleanly = 1)';
      } $c;
    })->catch (sub {
      my $error = $_[0];
      test {
        ok 0, $error;
      } $c, name => 'No rejection';
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 8, name => 'https - replied by server 1', timeout => 180;

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
    my $res;
    my @data;
    my $client = Web::Transport::BasicClient->new_from_url ($url, {
      tls_options => ({ca_file => Test::Certificates->ca_path ('cert.pem')}),
      proxy_manager => (pp [{protocol => 'http', host => $server->{host},
                                 port => $server->{port}}]),
    });
    $client->request (url => $url)->then (sub {
      $res = $_[0];
      $res->ws_send_binary ("\x80a\xA1");

      return reading {
        my $msg = $_[0];
        my $data = '';
        return Promise->resolve->then (sub {
          if (defined $msg->{text_body}) {
            return reading { $data .= ${$_[0]} } $msg->{text_body};
          } else {
            $res->ws_close;
            return reading { $data .= $_[0]->manakai_to_string } $msg->{body};
          }
        })->then (sub {
          if (@data and defined $data[-1]) {
            $data[-1] .= $data;
          } else {
            push @data, $data;
          }
        });
      } $res->ws_messages;
    })->then (sub {
      return $res->ws_close;
    })->then (sub {
      my ($res2) = $_[0];
      test {
        is 0+@data, 1;
        is $data[0], "\x80a\xA1";
        ok ! $res2->is_network_error;
        is $res2->status, 1005;
        is $res2->status_text, '';
        is $res2->ws_code, 1005;
        is $res2->ws_reason, '';
        is ''.$res2, 'WS closed (1005 || failed = 0, cleanly = 1)';
      } $c;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 8, name => 'proxy - https - replied by server', timeout => 180;

test {
  my $c = shift;
  my $url = Web::URL->parse_string (q<ws://test/foo/bar>);
  my $client = Web::Transport::BasicClient->new_from_url ($url);
  $client->request (url => undef)->catch (sub {
    my $res = $_[0];
    test {
      ok $res->is_network_error;
      is $res->status, 0;
      is $res->status_text, '';
      is $res->ws_code, 1006;
      is $res->ws_reason, '';
      like ''.$res, qr{^\QNetwork error: TypeError: No |url| argument\E};
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 6, name => 'No URL';

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
    ws-send-header opcode=8 length=0
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{ws://$server->{host}:$server->{port}/abc/def});
    my $res;
    my @data;
    my $client = Web::Transport::BasicClient->new_from_url ($url);
    $client->request (url => $url)->then (sub {
      $res = $_[0];
      $res->ws_close;

      return reading {
        my $msg = $_[0];
        my $data = '';
        return Promise->resolve->then (sub {
          if (defined $msg->{text_body}) {
            return reading { $data .= ${$_[0]} } $msg->{text_body};
          } else {
            return reading { $data .= $_[0]->manakai_to_string } $msg->{body};
          }
        })->then (sub {
          if (@data and defined $data[-1]) {
            $data[-1] .= $data;
          } else {
            push @data, $data;
          }
        });
      } $res->ws_messages;
    })->then (sub {
      return $res->ws_close;
    })->then (sub {
      my $res2 = $_[0];
      test {
        is 0+@data, 1;
        like $data[0], qr{^GET /abc/def HTTP/1.1};
        unlike $data[0], qr{Sec-WebSocket-Protocol:}i;
        ok ! $res2->is_network_error;
      } $c;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 4, name => 'ws_protocols none';

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
    ws-send-header opcode=8 length=0
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{ws://$server->{host}:$server->{port}/abc/def});
    my $res;
    my @data;
    my $client = Web::Transport::BasicClient->new_from_url ($url);
    $client->request (url => $url, ws_protocols => [])->then (sub {
      $res = $_[0];
      $res->ws_close;

      return reading {
        my $msg = $_[0];
        my $data = '';
        return Promise->resolve->then (sub {
          if (defined $msg->{text_body}) {
            return reading { $data .= ${$_[0]} } $msg->{text_body};
          } else {
            return reading { $data .= $_[0]->manakai_to_string } $msg->{body};
          }
        })->then (sub {
          if (@data and defined $data[-1]) {
            $data[-1] .= $data;
          } else {
            push @data, $data;
          }
        });
      } $res->ws_messages;
    })->then (sub {
      return $res->ws_close;
    })->then (sub {
      my $res2 = $_[0];
      test {
        is 0+@data, 1;
        like $data[0], qr{^GET /abc/def HTTP/1.1};
        unlike $data[0], qr{Sec-WebSocket-Protocol:}i;
        ok ! $res2->is_network_error;
      } $c;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 4, name => 'ws_protocols empty';

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
    "Sec-WebSocket-Protocol:  abc"CRLF
    "Connection: Upgrade"CRLF
    CRLF
    ws-send-header opcode=2 length=captured
    sendcaptured
    ws-send-header opcode=8 length=0
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{ws://$server->{host}:$server->{port}/abc/def});
    my $res;
    my @data;
    my $client = Web::Transport::BasicClient->new_from_url ($url);
    $client->request (url => $url, ws_protocols => ['abc'])->then (sub {
      $res = $_[0];
      $res->ws_close;

      return reading {
        my $msg = $_[0];
        my $data = '';
        return Promise->resolve->then (sub {
          if (defined $msg->{text_body}) {
            return reading { $data .= ${$_[0]} } $msg->{text_body};
          } else {
            return reading { $data .= $_[0]->manakai_to_string } $msg->{body};
          }
        })->then (sub {
          if (@data and defined $data[-1]) {
            $data[-1] .= $data;
          } else {
            push @data, $data;
          }
        });
      } $res->ws_messages;
    })->then (sub {
      return $res->ws_close;
    })->then (sub {
      my $res2 = $_[0];
      test {
        is 0+@data, 1;
        like $data[0], qr{^GET /abc/def HTTP/1.1};
        like $data[0], qr{^Sec-WebSocket-Protocol: abc\x0D\x0A}m;
        ok ! $res2->is_network_error;
      } $c;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 4, name => 'ws_protocols a value';

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
    "Sec-WebSocket-Protocol:  abc"CRLF
    "Connection: Upgrade"CRLF
    CRLF
    ws-send-header opcode=2 length=captured
    sendcaptured
    ws-send-header opcode=8 length=0
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{ws://$server->{host}:$server->{port}/abc/def});
    my $res;
    my @data;
    my $client = Web::Transport::BasicClient->new_from_url ($url);
    $client->request (url => $url, ws_protocols => ['abc', 'xa', '0'])->then (sub {
      $res = $_[0];
      $res->ws_close;

      return reading {
        my $msg = $_[0];
        my $data = '';
        return Promise->resolve->then (sub {
          if (defined $msg->{text_body}) {
            return reading { $data .= ${$_[0]} } $msg->{text_body};
          } else {
            return reading { $data .= $_[0]->manakai_to_string } $msg->{body};
          }
        })->then (sub {
          if (@data and defined $data[-1]) {
            $data[-1] .= $data;
          } else {
            push @data, $data;
          }
        });
      } $res->ws_messages;
    })->then (sub {
      return $res->ws_close;
    })->then (sub {
      my $res2 = $_[0];
      test {
        is 0+@data, 1;
        like $data[0], qr{^GET /abc/def HTTP/1.1};
        like $data[0], qr{^Sec-WebSocket-Protocol: abc,xa,0\x0D\x0A}m;
        ok ! $res2->is_network_error;
      } $c;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 4, name => 'ws_protocols values';

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
    "Sec-WebSocket-Protocol:  abc"CRLF
    "Connection: Upgrade"CRLF
    CRLF
    ws-send-header opcode=2 length=captured
    sendcaptured
    ws-send-header opcode=8 length=0
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{ws://$server->{host}:$server->{port}/abc/def});
    my $res;
    my @data;
    my $client = Web::Transport::BasicClient->new_from_url ($url);
    $client->request (url => $url, ws_protocols => ['abc', '', '0'])->then (sub {
      $res = $_[0];
      $res->ws_close;

      return reading {
        my $msg = $_[0];
        my $data = '';
        return Promise->resolve->then (sub {
          if (defined $msg->{text_body}) {
            return reading { $data .= ${$_[0]} } $msg->{text_body};
          } else {
            return reading { $data .= $_[0]->manakai_to_string } $msg->{body};
          }
        })->then (sub {
          if (@data and defined $data[-1]) {
            $data[-1] .= $data;
          } else {
            push @data, $data;
          }
        });
      } $res->ws_messages;
    })->then (sub {
      return $res->ws_close;
    })->then (sub {
      my $res2 = $_[0];
      test {
        is 0+@data, 1;
        like $data[0], qr{^GET /abc/def HTTP/1.1};
        like $data[0], qr{^Sec-WebSocket-Protocol: abc,,0\x0D\x0A}m;
        ok ! $res2->is_network_error;
      } $c;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 4, name => 'ws_protocols empty value';

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
    "Sec-WebSocket-Protocol:  abc"CRLF
    "Connection: Upgrade"CRLF
    CRLF
    ws-send-header opcode=2 length=captured
    sendcaptured
    ws-send-header opcode=8 length=0
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{ws://$server->{host}:$server->{port}/abc/def});
    my $client = Web::Transport::BasicClient->new_from_url ($url);
    $client->request (url => $url, ws_protocols => ["abc\x0A0"])->then (sub {
      test { ok 0 } $c;
    }, sub {
      my $res = $_[0];
      test {
        ok $res->is_network_error, $res;
        is $res->network_error_message, "Bad WebSocket protocol |abc\x0A0|";
      } $c;
    })->then (sub {
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => 'ws_protocols bad value';

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
    "Sec-WebSocket-Protocol:  abc"CRLF
    "Connection: Upgrade"CRLF
    CRLF
    ws-send-header opcode=2 length=captured
    sendcaptured
    ws-send-header opcode=8 length=0
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{ws://$server->{host}:$server->{port}/abc/def});
    my $client = Web::Transport::BasicClient->new_from_url ($url);
    $client->request (url => $url, ws_protocols => ["abc\x{100}0"])->then (sub {
      test { ok 0 } $c;
    }, sub {
      my $res = $_[0];
      test {
        ok $res->is_network_error, $res;
        is $res->network_error_message, "Bad WebSocket protocol |abc\x{100}0|";
      } $c;
    })->then (sub {
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => 'ws_protocols utf8 value';

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
    ws-send-header opcode=8 length=0
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{ws://$server->{host}:$server->{port}/abc/def});
    my $client = Web::Transport::BasicClient->new_from_url ($url);
    $client->request (url => $url, ws_protocols => ['abc'])->then (sub {
      test { ok 0 } $c;
    }, sub {
      my $res = $_[0];
      test {
        is $res->ws_code, 1006, $res;
      } $c;
    })->then (sub {
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'ws_protocols server unexpected value';

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
    "Sec-WebSocket-Protocol: xxx"CRLF
    "Connection: Upgrade"CRLF
    CRLF
    ws-send-header opcode=2 length=captured
    sendcaptured
    ws-send-header opcode=8 length=0
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{ws://$server->{host}:$server->{port}/abc/def});
    my $client = Web::Transport::BasicClient->new_from_url ($url);
    $client->request (url => $url, ws_protocols => ['abc'])->then (sub {
      test { ok 0 } $c;
    }, sub {
      my $res = $_[0];
      test {
        is $res->ws_code, 1006, $res;
      } $c;
    })->then (sub {
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'ws_protocols server returned unexpected value';

Test::Certificates->wait_create_cert;
run_tests;

=head1 LICENSE

Copyright 2016-2018 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
