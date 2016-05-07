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
use HTTPConnectionClient;

my $server_pids = {};
END { kill 'KILL', $_ for keys %$server_pids }
sub _server_as_cv ($$$$) {
  my ($host, $addr, $port, $code) = @_;
  my $cv = AE::cv;
  my $started;
  my $pid;
  my $data = '';
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
  return _server_as_cv ('localhost', '127.0.0.1', int (rand 10000) + 1024, $_[0]);
} # server_as_cv

my $test_path = path (__FILE__)->parent->parent->child ('local/test')->absolute;
$test_path->mkpath;

sub unix_server_as_cv ($) {
  return _server_as_cv ('localhost', 'unix/', $test_path->child (int (rand 10000) + 1024), $_[0]);
} # unix_server_as_cv

test {
  my $c = shift;
  server_as_cv (q{
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = qq{http://$server->{host}:$server->{port}/};
    my $client = HTTPConnectionClient->new_from_url ($url);
    my $p = $client->request ($url);
    test {
      isa_ok $p, 'Promise';
    } $c;
    return $p->then (sub {
      my $res = $_[0];
      test {
        isa_ok $res, 'HTTPConnectionClient::Response';
        ok $res->is_network_error;
        is $res->network_error_message, 'Connection closed without response';
        is $res->body_bytes, undef;
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 5, name => 'connection closed';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET"
    "HTTP/1.1 200 OK"CRLF
    "Content-Length: 4"CRLF
    CRLF
    "hoge"
    receive "GET"
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = qq{http://$server->{host}:$server->{port}/};
    my $client = HTTPConnectionClient->new_from_url ($url);
    return Promise->all ([
      $client->request ($url),
      $client->request ($url),
    ])->then (sub {
      my ($res1, $res2) = @{$_[0]};
      test {
        ok ! $res1->is_network_error;
        is $res1->network_error_message, undef;
        is $res1->body_bytes, 'hoge';

        ok ! $res2->is_network_error;
        is $res2->network_error_message, undef;
        is $res2->body_bytes, 'hoge';
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 6, name => 'connection closed (can_retry true)';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET"
    "HTTP/1.1 200 OK"CRLF
    "Content-Length: 4"CRLF
    CRLF
    "hoge"
    receive "GET"
    "H"
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = qq{http://$server->{host}:$server->{port}/};
    my $client = HTTPConnectionClient->new_from_url ($url);
    return Promise->all ([
      $client->request ($url),
      $client->request ($url),
    ])->then (sub {
      my ($res1, $res2) = @{$_[0]};
      test {
        ok ! $res1->is_network_error;
        is $res1->network_error_message, undef;
        is $res1->body_bytes, 'hoge';

        ok ! $res2->is_network_error;
        is $res2->network_error_message, undef;
        is $res2->body_bytes, 'H';
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 6, name => 'connection closed (can_retry false)';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET"
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = qq{http://$server->{host}:$server->{port}/};
    my $client = HTTPConnectionClient->new_from_url ($url);
    return Promise->all ([
      $client->request ($url),
      $client->request ($url),
    ])->then (sub {
      my ($res1, $res2) = @{$_[0]};
      test {
        ok $res1->is_network_error;
        is $res1->network_error_message, 'Connection closed without response';
        is $res1->body_bytes, undef;

        ok $res2->is_network_error;
        is $res2->network_error_message, 'Connection closed without response';
        is $res2->body_bytes, undef;
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 6, name => 'connection closed (1st response, can_retry false)';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET"
    "HTTP/1.1 200 OK"CRLF
    "Content-Length: 4"CRLF
    CRLF
    "hoge"
    receive "GET"
    "HTTP/1.1 200 OK"CRLF
    "Content-Length: 4"CRLF
    CRLF
    "fuga"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = qq{http://$server->{host}:$server->{port}/};
    my $client = HTTPConnectionClient->new_from_url ($url);
    return Promise->all ([
      $client->request ($url),
      $client->request ($url),
    ])->then (sub {
      my ($res1, $res2) = @{$_[0]};
      test {
        ok ! $res1->is_network_error;
        is $res1->network_error_message, undef;
        is $res1->body_bytes, 'hoge';

        ok ! $res2->is_network_error;
        is $res2->network_error_message, undef;
        is $res2->body_bytes, 'fuga';
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 6, name => 'connection persisted';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET"
    "HTTP/1.1 200 OK"CRLF
    "Content-Length: 4"CRLF
    CRLF
    "hoge"
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = qq{http://$server->{host}:$server->{port}/};
    my $client = HTTPConnectionClient->new_from_url ($url);
    return Promise->all ([
      $client->request ($url),
      $client->request ($url),
    ])->then (sub {
      my ($res1, $res2) = @{$_[0]};
      test {
        ok ! $res1->is_network_error;
        is $res1->network_error_message, undef;
        is $res1->body_bytes, 'hoge';

        ok ! $res2->is_network_error;
        is $res2->network_error_message, undef;
        is $res2->body_bytes, 'hoge';
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 6, name => 'connection not persisted';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET"
    "HTTP/1.1 201 OK ?"CRLF
    "Content-Length: 4"CRLF
    "X-Hoge: 4"CRLF
    "X-Hoge: 5"CRLF
    CRLF
    "hoge"
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = qq{http://$server->{host}:$server->{port}/};
    my $client = HTTPConnectionClient->new_from_url ($url);
    return Promise->all ([
      $client->request ($url),
    ])->then (sub {
      my ($res1) = @{$_[0]};
      test {
        ok ! $res1->is_network_error;
        is $res1->network_error_message, undef;
        is $res1->status, 201;
        is $res1->code, 201;
        ok $res1->is_success;
        ok ! $res1->is_error;
        is $res1->status_line, '201 OK ?';
        is $res1->header ('Hoge'), undef;
        is $res1->header ('X-Hoge'), '4';
        is $res1->header ('Content-length'), '4';
        is $res1->body_bytes, 'hoge';
        is $res1->content, 'hoge';
        is $res1->as_string, qq{HTTP/1.1 201 OK ?\x0D\x0AContent-Length: 4\x0D\x0AX-Hoge: 4\x0D\x0AX-Hoge: 5\x0D\x0A\x0D\x0Ahoge};
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 13, name => 'methods';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET"
    "HTTP/1.1 404 OK ?"CRLF
    "Content-Length: 4"CRLF
    "X-Hoge: 4"CRLF
    "X-Hoge: 5"CRLF
    CRLF
    "hoge"
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = qq{http://$server->{host}:$server->{port}/};
    my $client = HTTPConnectionClient->new_from_url ($url);
    return Promise->all ([
      $client->request ($url),
    ])->then (sub {
      my ($res1) = @{$_[0]};
      test {
        ok ! $res1->is_network_error;
        is $res1->network_error_message, undef;
        is $res1->status, 404;
        is $res1->code, 404;
        ok ! $res1->is_success;
        ok $res1->is_error;
        is $res1->status_line, '404 OK ?';
        is $res1->header ('Hoge'), undef;
        is $res1->header ('X-Hoge'), '4';
        is $res1->header ('Content-length'), '4';
        is $res1->body_bytes, 'hoge';
        is $res1->content, 'hoge';
        is $res1->as_string, qq{HTTP/1.1 404 OK ?\x0D\x0AContent-Length: 4\x0D\x0AX-Hoge: 4\x0D\x0AX-Hoge: 5\x0D\x0A\x0D\x0Ahoge};
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 13, name => 'methods';

test {
  my $c = shift;
  server_as_cv (q{
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = qq{http://$server->{host}:$server->{port}/};
    my $client = HTTPConnectionClient->new_from_url ($url);
    return Promise->all ([
      $client->request ($url),
    ])->then (sub {
      my ($res1) = @{$_[0]};
      test {
        ok $res1->is_network_error;
        is $res1->network_error_message, 'Connection closed without response';
        is $res1->status, 0;
        is $res1->code, 0;
        ok ! $res1->is_success;
        ok $res1->is_error;
        is $res1->status_line, '0 ';
        is $res1->header ('Hoge'), undef;
        is $res1->body_bytes, undef;
        is $res1->content, '';
        is $res1->as_string, qq{HTTP/1.1 0 \x0D\x0A\x0D\x0A};
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 11, name => 'methods';

test {
  my $c = shift;
  my $url1 = qq{http://hoge.example.com/};
  my $url2 = qq{http://fuga.example.com/};
  my $client = HTTPConnectionClient->new_from_url ($url1);
  return $client->request ($url2)->then (sub {
    test { ok 0 } $c;
  }, sub {
    my $error = $_[0];
    test {
      is $error, 'Bad origin |http://fuga.example.com| (|http://hoge.example.com| expected)';
    } $c;
  })->then (sub{
    return $client->close;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 1, name => 'origin mismatch';

test {
  my $c = shift;
  my $url1 = q{mailto:foo@bar};
  my $url2 = q{http://fuga.example.com/};
  my $client = HTTPConnectionClient->new_from_url ($url1);
  return $client->request ($url2)->then (sub {
    test { ok 0 } $c;
  }, sub {
    my $error = $_[0];
    test {
      is $error, 'Bad origin |http://fuga.example.com| (|| expected)';
    } $c;
  })->then (sub{
    return $client->close;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 1, name => 'origin mismatch';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET http://hoge.example.net/foo"
    "HTTP/1.1 203 Hoe"CRLF
    "Content-Length: 6"CRLF
    CRLF
    "abcdef"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = qq{http://hoge.example.net/foo};
    my $client = HTTPConnectionClient->new_from_url ($url);
    $client->proxies ([{protocol => 'http', host => $server->{host},
                        port => $server->{port}}]);
    return $client->request ($url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 203;
        is $res->body_bytes, 'abcdef';
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => 'http proxy';

test {
  my $c = shift;
  my $url = qq{http://hoge.example.net/foo};
  my $client = HTTPConnectionClient->new_from_url ($url);
  $client->proxies ([{protocol => 'http', host => 'hoge.fuga.test'}]);
  return $client->request ($url)->then (sub {
    my $res = $_[0];
    test {
      ok $res->is_network_error;
      is $res->network_error_message, "Can't resolve proxy host |hoge.fuga.test|";
    } $c;
  })->then (sub{
    return $client->close;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 2, name => 'http proxy bad';

test {
  my $c = shift;
  my $url = qq{http://hoge.example.net/foo};
  my $client = HTTPConnectionClient->new_from_url ($url);
  $client->proxies ([]);
  return $client->request ($url)->then (sub {
    my $res = $_[0];
    test {
      ok $res->is_network_error;
      is $res->network_error_message, "No proxy available";
    } $c;
  })->then (sub{
    return $client->close;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 2, name => 'no applicable proxy';

test {
  my $c = shift;
  my $url = qq{http://hoge.example.net/foo};
  my $client = HTTPConnectionClient->new_from_url ($url);
  $client->proxies ([{protocol => 'UnknownProtocol'}]);
  return $client->request ($url)->then (sub {
    my $res = $_[0];
    test {
      ok $res->is_network_error;
      is $res->network_error_message,
          "Proxy protocol |UnknownProtocol| not supported";
    } $c;
  })->then (sub{
    return $client->close;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 2, name => 'no applicable proxy';

test {
  my $c = shift;
  server_as_cv (q{
    starttls
    receive "GET http://hoge.example.net/foo"
    "HTTP/1.1 203 Hoe"CRLF
    "Content-Length: 6"CRLF
    CRLF
    "abcdef"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = qq{http://hoge.example.net/foo};
    my $client = HTTPConnectionClient->new_from_url ($url);
    $client->proxies ([{protocol => 'https', host => $server->{host},
                        port => $server->{port},
                        tls_options => {ca_file => Test::Certificates->ca_path ('cert.pem')}}]);
    return $client->request ($url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 203;
        is $res->body_bytes, 'abcdef';
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => 'https proxy';

test {
  my $c = shift;
  server_as_cv (q{
    starttls
    receive "GET /foo"
    "HTTP/1.1 203 Hoe"CRLF
    "Content-Length: 6"CRLF
    CRLF
    "abcdef"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = qq{https://$server->{host}:$server->{port}/foo};
    my $client = HTTPConnectionClient->new_from_url ($url);
    $client->tls_options ({ca_file => Test::Certificates->ca_path ('cert.pem')});
    return $client->request ($url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 203;
        is $res->body_bytes, 'abcdef';
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => 'https';

test {
  my $c = shift;
  server_as_cv (q{
    starttls
    receive "GET /foo"
    "HTTP/1.1 203 Hoe"CRLF
    "Content-Length: 6"CRLF
    CRLF
    "abcdef"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = qq{https://$server->{host}:$server->{port}/foo};
    my $client = HTTPConnectionClient->new_from_url ($url);
    return $client->request ($url)->then (sub {
      my $res = $_[0];
      test {
        ok $res->is_network_error;
        is $res->network_error_message, 'error:14090086:SSL routines:SSL3_GET_SERVER_CERTIFICATE:certificate verify failed';
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => 'https unknown CA';


test {
  my $c = shift;
  server_as_cv (q{
    receive "CONNECT hoge.example.net HTTP"
    "HTTP/1.1 200 OK"CRLF
    CRLF
    starttls
    receive "GET /foo"
    "HTTP/1.1 203 Hoe"CRLF
    "Content-Length: 6"CRLF
    CRLF
    "abcdef"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = qq{https://hoge.example.net/foo};
    my $client = HTTPConnectionClient->new_from_url ($url);
    $client->proxies ([{protocol => 'http', host => $server->{host},
                        port => $server->{port}}]);
    $client->tls_options
        ({ca_file => Test::Certificates->ca_path ('cert.pem')});
    return $client->request ($url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 203;
        is $res->body_bytes, 'abcdef';
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => 'http CONNECT proxy';

test {
  my $c = shift;
  server_as_cv (q{
    0x00
    90

    0x00
    0x00

    0x00
    0x00
    0x00
    0x00
    receive "GET /foo"
    "HTTP/1.1 203 Hoe"CRLF
    "Content-Length: 6"CRLF
    CRLF
    "abcdef"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = qq{http://$server->{host}/foo};
    my $client = HTTPConnectionClient->new_from_url ($url);
    $client->proxies ([{protocol => 'socks4', host => $server->{host},
                        port => $server->{port}}]);
    return $client->request ($url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 203;
        is $res->body_bytes, 'abcdef';
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => 'socks4 proxy';

test {
  my $c = shift;
  server_as_cv (q{
    0x00
    90

    0x00
    0x00

    0x00
    0x00
    0x00
    0x00
    receive "GET /foo"
    "HTTP/1.1 203 Hoe"CRLF
    "Content-Length: 6"CRLF
    CRLF
    "abcdef"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = qq{http://badhost.test/foo};
    my $client = HTTPConnectionClient->new_from_url ($url);
    $client->proxies ([{protocol => 'socks4', host => $server->{host},
                        port => $server->{port}}]);
    return $client->request ($url)->then (sub {
      my $res = $_[0];
      test {
        ok $res->is_network_error;
        is $res->network_error_message, "Can't resolve host |badhost.test|";
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => 'socks4 proxy not resolvable';

test {
  my $c = shift;
  server_as_cv (q{
    5
    0x00

    5
    0x00
    0x00

    0x01
    0x00
    0x00
    0x00
    0x00

    0x00
    0x00

    receive "GET /foo"
    "HTTP/1.1 203 Hoe"CRLF
    "Content-Length: 6"CRLF
    CRLF
    "abcdef"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = qq{http://hoge.test/foo};
    my $client = HTTPConnectionClient->new_from_url ($url);
    $client->proxies ([{protocol => 'socks5', host => $server->{host},
                        port => $server->{port}}]);
    return $client->request ($url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 203;
        is $res->body_bytes, 'abcdef';
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => 'socks5 proxy';

test {
  my $c = shift;
  unix_server_as_cv (q{
    receive "GET /foo"
    "HTTP/1.1 203 Hoe"CRLF
    "Content-Length: 6"CRLF
    CRLF
    "abcdef"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = qq{http://hoge.test/foo};
    my $client = HTTPConnectionClient->new_from_url ($url);
    $client->proxies ([{protocol => 'unix', path => $server->{port}}]);
    return $client->request ($url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 203;
        is $res->body_bytes, 'abcdef';
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => 'unix socket proxy';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = qq{http://$server->{host}:$server->{port}/};
    my $client = HTTPConnectionClient->new_from_url ($url);
    $client->last_resort_timeout (0.1);
    my $p = $client->request ($url);
    test {
      isa_ok $p, 'Promise';
    } $c;
    return $p->then (sub {
      my $res = $_[0];
      test {
        isa_ok $res, 'HTTPConnectionClient::Response';
        ok $res->is_network_error;
        is $res->network_error_message, 'Connection closed without response';
        is $res->body_bytes, undef;
        ok ! $res->incomplete;
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 6, name => 'timeout';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET"
    "HTTP/1.0 200 OK"CRLF
    CRLF
    "hoge"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = qq{http://$server->{host}:$server->{port}/};
    my $client = HTTPConnectionClient->new_from_url ($url);
    $client->last_resort_timeout (0.1);
    my $p = $client->request ($url);
    test {
      isa_ok $p, 'Promise';
    } $c;
    return $p->then (sub {
      my $res = $_[0];
      test {
        isa_ok $res, 'HTTPConnectionClient::Response';
        ok ! $res->is_network_error;
        is $res->network_error_message, undef;
        is $res->body_bytes, 'hoge';
        ok $res->incomplete;
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 6, name => 'timeout incomplete response';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET"
    "HTTP/1.0 200 OK"CRLF
    "content-length: 2"CRLF
    CRLF
    "ho"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = qq{http://$server->{host}:$server->{port}/};
    my $client = HTTPConnectionClient->new_from_url ($url);
    $client->last_resort_timeout (0.1);
    my $p = $client->request ($url);
    test {
      isa_ok $p, 'Promise';
    } $c;
    return $p->then (sub {
      my $res = $_[0];
      test {
        isa_ok $res, 'HTTPConnectionClient::Response';
        ok ! $res->is_network_error;
        is $res->network_error_message, undef;
        is $res->body_bytes, 'ho';
        ok ! $res->incomplete;
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 6, name => 'timeout not incomplete response';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET"
    "HT"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = qq{http://$server->{host}:$server->{port}/};
    my $client = HTTPConnectionClient->new_from_url ($url);
    $client->last_resort_timeout (0.1);
    my $p = $client->request ($url);
    test {
      isa_ok $p, 'Promise';
    } $c;
    return $p->then (sub {
      my $res = $_[0];
      test {
        isa_ok $res, 'HTTPConnectionClient::Response';
        ok ! $res->is_network_error;
        is $res->network_error_message, undef;
        is $res->body_bytes, 'HT';
        ok $res->incomplete;
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 6, name => 'timeout HTTP/0.9 incomplete response';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET"
    "HTTP/1.1 200 OK"CRLF
    "Content-Length: 4"CRLF
    CRLF
    "hoge"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = qq{http://$server->{host}:$server->{port}/};
    my $client = HTTPConnectionClient->new_from_url ($url);
    return Promise->all ([
      $client->request ($url),
      $client->last_resort_timeout (0.5) && $client->request ($url),
    ])->then (sub {
      my ($res1, $res2) = @{$_[0]};
      test {
        ok ! $res1->is_network_error;
        is $res1->network_error_message, undef;
        is $res1->body_bytes, 'hoge';

        ok $res2->is_network_error;
        is $res2->network_error_message, 'Connection closed without response';
        is $res2->body_bytes, undef;
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 6, name => 'timeout can retry';

test {
  my $c = shift;
  my $url = q{ftp://127.0.0.1/foo};
  my $client = HTTPConnectionClient->new_from_url ($url);
  return $client->request ($url)->then (sub {
    my $res = $_[0];
    test {
      ok $res->is_network_error;
      is $res->network_error_message, "Bad URL scheme |ftp|";
    } $c;
  })->then (sub{
    return $client->close;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 2, name => 'bad url scheme';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET ftp://hoge.example.net/foo"
    "HTTP/1.1 203 Hoe"CRLF
    "Content-Length: 6"CRLF
    CRLF
    "abcdef"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = qq{ftp://hoge.example.net/foo};
    my $client = HTTPConnectionClient->new_from_url ($url);
    $client->proxies ([{protocol => 'http', host => $server->{host},
                        port => $server->{port}}]);
    return $client->request ($url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 203;
        is $res->body_bytes, 'abcdef';
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => 'bad url scheme http proxy - ftp';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET hoge://hoge.example.net/foo"
    "HTTP/1.1 203 Hoe"CRLF
    "Content-Length: 6"CRLF
    CRLF
    "abcdef"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = qq{hoge://hoge.example.net/foo};
    my $client = HTTPConnectionClient->new_from_url ($url);
    $client->proxies ([{protocol => 'http', host => $server->{host},
                        port => $server->{port}}]);
    return $client->request ($url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 203;
        is $res->body_bytes, 'abcdef';
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => 'bad url scheme http proxy - unknown scheme';

test {
  my $c = shift;
  server_as_cv (q{
    0x00
    90

    0x00
    0x00

    0x00
    0x00
    0x00
    0x00
    receive "GET /foo"
    "HTTP/1.1 203 Hoe"CRLF
    "Content-Length: 6"CRLF
    CRLF
    "abcdef"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = qq{ftp://$server->{host}/foo};
    my $client = HTTPConnectionClient->new_from_url ($url);
    $client->proxies ([{protocol => 'socks4', host => $server->{host},
                        port => $server->{port}}]);
    return $client->request ($url)->then (sub {
      my $res = $_[0];
      test {
        ok $res->is_network_error;
        is $res->network_error_message, 'Bad URL scheme |ftp|';
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => 'bad url scheme - socks4 proxy';

test {
  my $c = shift;
  server_as_cv (q{
    0x00
    90

    0x00
    0x00

    0x00
    0x00
    0x00
    0x00
    receive "GET /foo"
    "HTTP/1.1 203 Hoe"CRLF
    "Content-Length: 6"CRLF
    CRLF
    "abcdef"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = qq{gopher://$server->{host}/foo};
    my $client = HTTPConnectionClient->new_from_url ($url);
    $client->proxies ([{protocol => 'socks4', host => $server->{host},
                        port => $server->{port}}]);
    return $client->request ($url)->then (sub {
      my $res = $_[0];
      test {
        ok $res->is_network_error;
        is $res->network_error_message, 'Bad URL scheme |gopher|';
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => 'bad url scheme - socks4 proxy';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET http://hoge.example.net/foo"
    "HTTP/1.1 203 Hoe"CRLF
    "Content-Length: 6"CRLF
    CRLF
    "abcdef"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = qq{http://hoge.example.net/foo};
    my $client = HTTPConnectionClient->new_from_url ($url);
    $client->proxies ([{protocol => 'http', host => 'unknown.host.test'},
                       {protocol => 'http', host => $server->{host},
                        port => $server->{port}}]);
    return $client->request ($url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 203;
        is $res->body_bytes, 'abcdef';
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => 'proxy fallback';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET /foo"
    "HTTP/1.1 203 Hoe"CRLF
    "Content-Length: 6"CRLF
    CRLF
    "abcdef"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = qq{http://$server->{host}:$server->{port}/foo};
    my $client = HTTPConnectionClient->new_from_url ($url);
    $client->proxies ([{protocol => 'http', host => 'unknown.host.test'},
                       {protocol => 'tcp'}]);
    return $client->request ($url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 203;
        is $res->body_bytes, 'abcdef';
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => 'proxy fallback';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET /foo"
    "HTTP/1.1 203 Hoe"CRLF
    CRLF
    "abcdef"
    sleep 2
    "xyzaaa"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = qq{http://$server->{host}:$server->{port}/foo};
    my $client = HTTPConnectionClient->new_from_url ($url);
    $client->max_size (6);
    return $client->request ($url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 203;
        is $res->body_bytes, 'abcdef';
        ok $res->incomplete;
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 3, name => 'max_size';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET /foo"
    "HTTP/1.1 203 Hoe"CRLF
    "content-length: 6"CRLF
    CRLF
    "abcdef"
    sleep 2
    "xyzaaa"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = qq{http://$server->{host}:$server->{port}/foo};
    my $client = HTTPConnectionClient->new_from_url ($url);
    $client->max_size (6);
    return $client->request ($url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 203;
        is $res->body_bytes, 'abcdef';
        ok ! $res->incomplete;
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 3, name => 'max_size';

run_tests;
