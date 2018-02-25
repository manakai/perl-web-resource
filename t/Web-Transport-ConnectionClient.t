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
use Web::Transport::ConnectionClient;
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

my $test_path = path (__FILE__)->parent->parent->child ('local/test')->absolute;
$test_path->mkpath;

sub unix_server_as_cv ($) {
  return _server_as_cv ('localhost', 'unix/', $test_path->child (int (rand 10000) + 1024), $_[0]);
} # unix_server_as_cv

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

test {
  my $c = shift;
  eval {
    Web::Transport::ConnectionClient->new_from_url;
  };
  like $@, qr{^No URL is specified at \Q@{[__FILE__]}\E line @{[__LINE__-2]}};
  done $c;
} n => 1, name => 'new_from_url no url';

test {
  my $c = shift;
  my $url = Web::URL->parse_string ('about:blank');
  eval {
    Web::Transport::ConnectionClient->new_from_url ($url);
  };
  ok $@;
  done $c;
} n => 1, name => 'new_from_url no url';

test {
  my $c = shift;
  eval {
    Web::Transport::ConnectionClient->new_from_host (undef);
  };
  ok $@;
  done $c;
} n => 1, name => 'new_from_host undef';

test {
  my $c = shift;
  eval {
    Web::Transport::ConnectionClient->new_from_host ("foo:bar");
  };
  ok $@;
  done $c;
} n => 1, name => 'new_from_host invalid';

test {
  my $c = shift;
  eval {
    Web::Transport::ConnectionClient->new_from_host ("[13.44:554:5");
  };
  ok $@;
  done $c;
} n => 1, name => 'new_from_host invalid';

test {
  my $c = shift;
  my $client = Web::Transport::ConnectionClient->new_from_host ('hoge.test');
  isa_ok $client, 'Web::Transport::ConnectionClient';
  isa_ok $client->origin, 'Web::Origin';
  is $client->origin->to_ascii, 'https://hoge.test';
  done $c;
} n => 3, name => 'new_from_host domain';

test {
  my $c = shift;
  my $client = Web::Transport::ConnectionClient->new_from_host ('192.168.000.01');
  isa_ok $client, 'Web::Transport::ConnectionClient';
  isa_ok $client->origin, 'Web::Origin';
  is $client->origin->to_ascii, 'https://192.168.0.1';
  done $c;
} n => 3, name => 'new_from_host ipv4';

test {
  my $c = shift;
  my $client = Web::Transport::ConnectionClient->new_from_host ('[0::1]');
  isa_ok $client, 'Web::Transport::ConnectionClient';
  isa_ok $client->origin, 'Web::Origin';
  is $client->origin->to_ascii, 'https://[::1]';
  done $c;
} n => 3, name => 'new_from_host ipv6';

test {
  my $c = shift;
  my $client = Web::Transport::ConnectionClient->new_from_host ("\x{5000}\x{5200}\x{3002}");
  isa_ok $client, 'Web::Transport::ConnectionClient';
  isa_ok $client->origin, 'Web::Origin';
  is $client->origin->to_ascii, 'https://xn--rvqq2c.';
  done $c;
} n => 3, name => 'new_from_host domain IDN';

test {
  my $c = shift;
  my $url1 = Web::URL->parse_string ('http://test/');
  my $client = Web::Transport::ConnectionClient->new_from_url ($url1);
  my $p = $client->request (url => undef);
  isa_ok $p, 'Promise';
  $p->then (sub {
    test { ok 0 } $c;
  }, sub {
    my $result = $_[0];
    test {
      ok $result->{failed};
      is $result->{message}, "No |url| argument";
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 3, name => 'request no url';

test {
  my $c = shift;
  my $url1 = Web::URL->parse_string ('http://test/');
  my $client = Web::Transport::ConnectionClient->new_from_url ($url1);
  isa_ok $client->origin, 'Web::Origin';
  is $client->origin->to_ascii, 'http://test';
  my $url2 = Web::URL->parse_string ('foo:bar');
  my $p = $client->request (url => $url2);
  isa_ok $p, 'Promise';
  $p->then (sub {
    test { ok 0 } $c;
  }, sub {
    my $result = $_[0];
    test {
      ok $result->{failed};
      is $result->{message}, "Bad URL origin |null| (|http://test| expected)";
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 5, name => 'request opaque origin';

test {
  my $c = shift;
  server_as_cv (q{
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}/});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    my $p = $client->request (url => $url);
    test {
      isa_ok $p, 'Promise';
    } $c;
    return $p->then (sub {
      my $res = $_[0];
      test {
        isa_ok $res, 'Web::Transport::Response';
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
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}/});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    return Promise->all ([
      $client->request (url => $url),
      $client->request (url => $url),
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
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}/});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    return Promise->all ([
      $client->request (url => $url),
      $client->request (url => $url),
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
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}/});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    return Promise->all ([
      $client->request (url => $url),
      $client->request (url => $url),
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
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}/});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    return Promise->all ([
      $client->request (url => $url),
      $client->request (url => $url),
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
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}/});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    return Promise->all ([
      $client->request (url => $url),
      $client->request (url => $url),
    ])->then (sub {
      my ($res1, $res2) = @{$_[0]};
      test {
        ok ! $res1->is_network_error, $res1;
        is $res1->network_error_message, undef;
        is $res1->body_bytes, 'hoge';

        ok ! $res2->is_network_error, $res2;
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
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}/});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    return Promise->all ([
      $client->request (url => $url),
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
        is $res1->header ('X-Hoge'), '4, 5';
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
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}/});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    return Promise->all ([
      $client->request (url => $url),
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
        is $res1->header ('X-Hoge'), '4, 5';
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
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}/});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    return Promise->all ([
      $client->request (url => $url),
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
  my $url1 = Web::URL->parse_string (qq{http://hoge.example.com/});
  my $url2 = Web::URL->parse_string (qq{http://fuga.example.com/});
  my $client = Web::Transport::ConnectionClient->new_from_url ($url1);
  return $client->request (url => $url2)->then (sub {
    test { ok 0 } $c;
  }, sub {
    my $error = $_[0];
    test {
      is $error->network_error_message, 'Bad URL origin |http://fuga.example.com| (|http://hoge.example.com| expected)';
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
  my $url1 = Web::URL->parse_string (qq{http://hoge.example.com/});
  my $url2 = Web::URL->parse_string (qq{mailto:hoge});
  my $client = Web::Transport::ConnectionClient->new_from_url ($url1);
  return $client->request (url => $url2)->then (sub {
    test { ok 0 } $c;
  }, sub {
    my $error = $_[0];
    test {
      is $error->network_error_message, 'Bad URL origin |null| (|http://hoge.example.com| expected)';
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
  my $url1 = Web::URL->parse_string (q{mailto:foo@bar});
  eval {
    Web::Transport::ConnectionClient->new_from_url ($url1);
  };
  like $@, qr{^The URL does not have a tuple origin};
  done $c;
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
    my $url = Web::URL->parse_string (qq{http://hoge.example.net/foo});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    $client->proxy_manager (pp [{protocol => 'http', host => $server->{host},
                        port => $server->{port}}]);
    return $client->request (url => $url)->then (sub {
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
  my $url = Web::URL->parse_string (qq{http://hoge.example.net/foo});
  my $client = Web::Transport::ConnectionClient->new_from_url ($url);
  $client->proxy_manager (pp [{protocol => 'http', host => 'hoge.fuga.test'}]);
  return $client->request (url => $url)->then (sub {
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
  my $url = Web::URL->parse_string (qq{http://hoge.example.net/foo});
  my $client = Web::Transport::ConnectionClient->new_from_url ($url);
  $client->proxy_manager (pp []);
  return $client->request (url => $url)->then (sub {
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
  my $url = Web::URL->parse_string (qq{http://hoge.example.net/foo});
  my $client = Web::Transport::ConnectionClient->new_from_url ($url);
  $client->proxy_manager (pp [{protocol => 'UnknownProtocol'}]);
  return $client->request (url => $url)->then (sub {
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
  server_as_cv (q(
    starttls host=resolver1.test
    receive "GET http://hoge.example.net/foo"
    "HTTP/1.1 203 Hoe"CRLF
    "Content-Length: 6"CRLF
    CRLF
    "abcdef"
  ))->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://hoge.example.net/foo});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    $client->resolver (bless {'resolver1.test' => '127.0.0.1'}, 'test::resolver1');
    $client->proxy_manager (pp [{protocol => 'https',
                                 host => 'resolver1.test', #$server->{host},
                                 port => $server->{port},
                                 tls_options => {ca_file => Test::Certificates->ca_path ('cert.pem')}}]);
    return $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        is $res->network_error_message, undef;
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
} n => 3, name => 'https proxy';

test {
  my $c = shift;
  server_as_cv (q{
    starttls host=hoge.example.net
    receive "GET http://hoge.example.net/foo"
    "HTTP/1.1 203 Hoe"CRLF
    "Content-Length: 6"CRLF
    CRLF
    "abcdef"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://hoge.example.net/foo});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    $client->resolver (bless {'resolver1.test' => '127.0.0.1'}, 'test::resolver1');
    $client->proxy_manager (pp [{protocol => 'https', host => $server->{host},
                        port => $server->{port},
                        tls_options => {ca_file => Test::Certificates->ca_path ('cert.pem')}}]);
    return $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        ok $res->is_network_error;
        ok $res->network_error_message;
        #'error:14090086:SSL routines:SSL3_GET_SERVER_CERTIFICATE:certificate verify failed';
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => 'https proxy bad service identity';

test {
  my $c = shift;
  server_as_cv (q{
    starttls host=host2.test
    receive "GET /foo"
    "HTTP/1.1 203 Hoe"CRLF
    "Content-Length: 6"CRLF
    CRLF
    "abcdef"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{https://host2.test:$server->{port}/foo});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    $client->resolver (bless {'host2.test' => '127.0.0.1'}, 'test::resolver1');
    $client->tls_options ({ca_file => Test::Certificates->ca_path ('cert.pem')});
    return $client->request (url => $url)->then (sub {
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
    starttls host=host3.test
    receive "GET /foo"
    "HTTP/1.1 203 Hoe"CRLF
    CRLF
    "abcdef"
    write sni_host
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{https://host3.test:$server->{port}/foo});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    $client->resolver (bless {'host3.test' => '127.0.0.1'}, 'test::resolver1');
    $client->tls_options ({ca_file => Test::Certificates->ca_path ('cert.pem')});
    return $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 203;
        is $res->body_bytes, 'abcdef' . 'host3.test';
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => 'https SNI';

test {
  my $c = shift;
  server_as_cv (q{
    starttls host=another.host.test
    receive "GET /foo"
    "HTTP/1.1 203 Hoe"CRLF
    "Content-Length: 6"CRLF
    CRLF
    "abcdef"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{https://host4.test:$server->{port}/foo});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    $client->resolver (bless {'host4.test' => '127.0.0.1'}, 'test::resolver1');
    $client->tls_options ({ca_file => Test::Certificates->ca_path ('cert.pem')});
    return $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        ok $res->is_network_error;
        if ($res->network_error_message eq 'Certificate verification error 1 - error number 1') {
          ## Not sure whether this is the right error...
          is $res->network_error_message, 'Certificate verification error 1 - error number 1';
        } else {
          #'error:14090086:SSL routines:SSL3_GET_SERVER_CERTIFICATE:certificate verify failed'
          #'error:14007086:SSL routines:CONNECT_CR_CERT:certificate verify failed'
          like $res->network_error_message, qr{certificate verify failed};
        }
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => 'https bad service identity';

test {
  my $c = shift;
  server_as_cv (q{
    starttls host=host5.test
    receive "GET /foo"
    "HTTP/1.1 203 Hoe"CRLF
    "Content-Length: 6"CRLF
    CRLF
    "abcdef"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{https://host5.test:$server->{port}/foo});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    $client->resolver (bless {'host5.test' => '127.0.0.1'}, 'test::resolver1');
    return $client->request (url => $url)->then (sub {
      my $res = $_[0];
      test {
        ok $res->is_network_error;
        ok $res->network_error_message;
        #'Certificate verification error 20 - unable to get local issuer certificate';
        #'error:14090086:SSL routines:SSL3_GET_SERVER_CERTIFICATE:certificate verify failed';
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
    starttls host=hoge.example.net
    receive "GET /foo"
    "HTTP/1.1 203 Hoe"CRLF
    "Content-Length: 6"CRLF
    CRLF
    "abcdef"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{https://hoge.example.net/foo});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    $client->proxy_manager (pp [{protocol => 'http', host => $server->{host},
                                 port => $server->{port}}]);
    $client->tls_options
        ({ca_file => Test::Certificates->ca_path ('cert.pem')});
    return $client->request (url => $url)->then (sub {
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
  unix_server_as_cv (q{
    receive "GET /foo"
    "HTTP/1.1 203 Hoe"CRLF
    "Content-Length: 6"CRLF
    CRLF
    "abcdef"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://hoge.test/foo});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    $client->proxy_manager (pp [{protocol => 'unix', path => $server->{port}}]);
    return $client->request (url => $url)->then (sub {
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
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}/});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    $client->last_resort_timeout (0.5);
    my $p = $client->request (url => $url);
    test {
      isa_ok $p, 'Promise';
    } $c;
    return $p->then (sub {
      my $res = $_[0];
      test {
        isa_ok $res, 'Web::Transport::Response';
        ok $res->is_network_error;
        is $res->network_error_message, 'Last-resort timeout (0.5)';
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
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}/});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    $client->last_resort_timeout (0.5);
    my $p = $client->request (url => $url);
    test {
      isa_ok $p, 'Promise';
    } $c;
    return $p->then (sub {
      my $res = $_[0];
      test {
        isa_ok $res, 'Web::Transport::Response';
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
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}/});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    $client->last_resort_timeout (0.5);
    my $p = $client->request (url => $url);
    test {
      isa_ok $p, 'Promise';
    } $c;
    return $p->then (sub {
      my $res = $_[0];
      test {
        isa_ok $res, 'Web::Transport::Response';
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
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}/});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    $client->last_resort_timeout (0.5);
    my $p = $client->request (url => $url);
    test {
      isa_ok $p, 'Promise';
    } $c;
    return $p->then (sub {
      my $res = $_[0];
      test {
        isa_ok $res, 'Web::Transport::Response';
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
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}/});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    return Promise->all ([
      $client->request (url => $url),
      $client->last_resort_timeout (0.5) && $client->request (url => $url),
    ])->then (sub {
      my ($res1, $res2) = @{$_[0]};
      test {
        ok ! $res1->is_network_error;
        is $res1->network_error_message, undef;
        is $res1->body_bytes, 'hoge';

        ok $res2->is_network_error;
        is $res2->network_error_message, 'Last-resort timeout (0.5)';
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
  server_as_cv (q{
    receive "GET http://hoge.example.net/foo"
    "HTTP/1.1 203 Hoe"CRLF
    "Content-Length: 6"CRLF
    CRLF
    "abcdef"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://hoge.example.net/foo});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    $client->proxy_manager (pp [{protocol => 'http', host => 'unknown.host.test'},
                       {protocol => 'http', host => $server->{host},
                        port => $server->{port}}]);
    return $client->request (url => $url)->then (sub {
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
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}/foo});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    $client->proxy_manager (pp [{protocol => 'http', host => 'unknown.host.test'},
                       {protocol => 'tcp'}]);
    return $client->request (url => $url)->then (sub {
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
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}/foo});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    $client->max_size (6);
    return $client->request (url => $url)->then (sub {
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
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}/foo});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    $client->max_size (6);
    return $client->request (url => $url)->then (sub {
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

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET", start capture
    receive CRLFCRLF, end capture
    "HTTP/1.1 203 Hoe"CRLF
    CRLF
    sendcaptured
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}/foo});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    return $client->request (url => $url, headers => {
      'X-hoge' => 124,
    })->then (sub {
      my $res = $_[0];
      test {
        my $headers = $res->body_bytes;
        like $headers, qr{\x0AHost: \Q$server->{host}\E};
        like $headers, qr{\x0AUser-Agent: Mozilla/.+WebKit.+Gecko};
        like $headers, qr{\x0AAccept: \*/\*\x0D\x0A};
        like $headers, qr{\x0AAccept-Language: en-US\x0D\x0A};
        like $headers, qr{\x0AX-hoge: 124\x0D\x0A};
        unlike $headers, qr{\x0AContent-Type: }i;
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 6, name => 'request options';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET", start capture
    receive CRLFCRLF, end capture
    "HTTP/1.1 203 Hoe"CRLF
    CRLF
    sendcaptured
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}/foo});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    return $client->request (url => $url, headers => {
      'X-hoge' => [124, "abc def", 0, ''],
    })->then (sub {
      my $res = $_[0];
      test {
        my $headers = $res->body_bytes;
        like $headers, qr{\x0AX-hoge: 124\x0D\x0A};
        like $headers, qr{\x0AX-hoge: abc def\x0D\x0A};
        like $headers, qr{\x0AX-hoge: 0\x0D\x0A};
        like $headers, qr{\x0AX-hoge: \x0D\x0A};
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 4, name => 'request options';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET", start capture
    receive CRLFCRLF, end capture
    "HTTP/1.1 203 Hoe"CRLF
    CRLF
    sendcaptured
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}/foo});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    return $client->request (url => $url, headers => {
      'X-hoge' => "ab\x0A\x0Dxy",
    })->then (sub {
      my $res = $_[0];
      test {
        my $headers = $res->body_bytes;
        like $headers, qr{\x0AX-hoge: ab  xy\x0D\x0A};
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'request options';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET", start capture
    receive CRLFCRLF, end capture
    "HTTP/1.1 203 Hoe"CRLF
    CRLF
    sendcaptured
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}/foo});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    return $client->request (url => $url, headers => {
      'X-hoge' => undef,
    })->then (sub {
      my $res = $_[0];
      test {
        my $headers = $res->body_bytes;
        unlike $headers, qr{\x0AX-hoge: };
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'request options';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET", start capture
    receive CRLFCRLF, end capture
    "HTTP/1.1 203 Hoe"CRLF
    CRLF
    sendcaptured
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}/foo});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    return $client->request (url => $url, headers => {
      'X-hoge' => [undef],
    })->then (sub {
      my $res = $_[0];
      test {
        my $headers = $res->body_bytes;
        like $headers, qr{\x0AX-hoge: \x0D\x0A};
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'request options';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET", start capture
    receive CRLFCRLF, end capture
    "HTTP/1.1 203 Hoe"CRLF
    CRLF
    sendcaptured
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}/foo});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    return $client->request (url => $url, headers => {
      'X-hoge' => ["\xFE\x80\x9F\xAB", "\x{5400}\x{100}\xFE"],
    })->then (sub {
      my $res = $_[0];
      test {
        my $headers = $res->body_bytes;
        like $headers, qr{\x0AX-hoge: \xC3\xBE\xC2\x80\xC2\x9F\xC2\xAB\x0D\x0A};
        like $headers, qr{\x0AX-hoge: \xE5\x90\x80\xC4\x80\xC3\xBE\x0D\x0A};
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => 'request options';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET", start capture
    receive CRLFCRLF, end capture
    "HTTP/1.1 203 Hoe"CRLF
    CRLF
    sendcaptured
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}/foo});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    return $client->request (url => $url, superreload => 1)->then (sub {
      my $res = $_[0];
      test {
        my $headers = $res->body_bytes;
        like $headers, qr{\x0ACache-Control: no-cache\x0D\x0A};
        like $headers, qr{\x0APragma: no-cache\x0D\x0A};
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => 'request options - superreload';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET", start capture
    receive CRLFCRLF, end capture
    "HTTP/1.1 203 Hoe"CRLF
    CRLF
    sendcaptured
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}/foo});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    return $client->request (url => $url, headers => {
      'X-WSSE' => 'hoge faug',
    })->then (sub {
      my $res = $_[0];
      test {
        my $headers = $res->body_bytes;
        like $headers, qr{\x0AX-WSSE: hoge faug\x0D\x0A};
        like $headers, qr{\x0ACache-Control: no-store\x0D\x0A};
        like $headers, qr{\x0APragma: no-cache\x0D\x0A};
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 3, name => 'request options - X-WSSE: header';

test {
  my $c = shift;
  server_as_cv (q{
    receive "DELETE", start capture
    receive CRLFCRLF, end capture
    "HTTP/1.1 203 Hoe"CRLF
    CRLF
    sendcaptured
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}/foo});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    return $client->request (url => $url, method => 'DELETE')->then (sub {
      my $res = $_[0];
      test {
        my $headers = $res->body_bytes;
        like $headers, qr{DELETE /foo HTTP};
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'request options';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET", start capture
    receive CRLFCRLF, end capture
    "HTTP/1.1 203 Hoe"CRLF
    CRLF
    sendcaptured
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}/foo});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    return $client->request (url => $url, params => {
      foo => undef,
      bar => ['abc', '123'],
    })->then (sub {
      my $res = $_[0];
      test {
        my $headers = $res->body_bytes;
        like $headers, qr{GET /foo\?bar=abc&bar=123};
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'request options - params';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET", start capture
    receive CRLFCRLF, end capture
    "HTTP/1.1 203 Hoe"CRLF
    CRLF
    sendcaptured
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}/foo});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    return $client->request (url => $url, params => {
      foo => undef,
      bar => [undef, 0, ''],
    })->then (sub {
      my $res = $_[0];
      test {
        my $headers = $res->body_bytes;
        like $headers, qr{GET /foo\?bar=0&bar=};
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'request options - params';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET", start capture
    receive CRLFCRLF, end capture
    "HTTP/1.1 203 Hoe"CRLF
    CRLF
    sendcaptured
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}/foo});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    return $client->request (url => $url, params => {
      "\x{5000}" => "\x{4000}",
    })->then (sub {
      my $res = $_[0];
      test {
        my $headers = $res->body_bytes;
        like $headers, qr{GET /foo\?%E5%80%80=%E4%80%80};
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'request options - params';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET", start capture
    receive CRLFCRLF, end capture
    "HTTP/1.1 203 Hoe"CRLF
    CRLF
    sendcaptured
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}/foo});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    return $client->request (url => $url, params => {
      "\x80" => "\xFE",
    })->then (sub {
      my $res = $_[0];
      test {
        my $headers = $res->body_bytes;
        like $headers, qr{GET /foo\?%C2%80=%C3%BE};
        unlike $headers, qr{Content-Type}i;
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => 'request options - params';

test {
  my $c = shift;
  server_as_cv (q{
    receive "POST", start capture
    "HTTP/1.1 203 Hoe"CRLF
    "content-length: 0"CRLF
    CRLF
    receive "GET", end capture
    "HTTP/1.1 200 OK"CRLF
    CRLF
    sendcaptured
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}/foo});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    return $client->request (url => $url, params => {
      "\x80" => "\xFE",
    }, method => 'POST')->then (sub {
      return $client->request (url => $url);
    })->then (sub {
      my $res = $_[0];
      test {
        my $request = $res->body_bytes;
        $request =~ s/GET$//;
        like $request, qr{\x0AContent-Type: application/x-www-form-urlencoded\x0D\x0A};
        like $request, qr{\x0AContent-Length: 13\x0D\x0A};
        like $request, qr{\x0D\x0A\x0D\x0A%C2%80=%C3%BE};
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 3, name => 'request options - params as body';

test {
  my $c = shift;
  server_as_cv (q{
    receive "POST", start capture
    "HTTP/1.1 203 Hoe"CRLF
    "content-length: 0"CRLF
    CRLF
    receive "GET", end capture
    "HTTP/1.1 200 OK"CRLF
    CRLF
    sendcaptured
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}/foo});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    return $client->request (url => $url, params => {
      "\x80" => "\xFE",
    }, body => "\xFE\x84", method => 'POST')->then (sub {
      return $client->request (url => $url);
    })->then (sub {
      my $res = $_[0];
      test {
        my $request = $res->body_bytes;
        $request =~ s/GET$//;
        unlike $request, qr{\x0AContent-Type:};
        like $request, qr{\x0AContent-Length: 2\x0D\x0A};
        like $request, qr{\x0D\x0A\x0D\x0A\xFE\x84$};
        like $request, qr{/foo\?%C2%80=%C3%BE};
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 4, name => 'request options - params and body';

test {
  my $c = shift;
  server_as_cv (q{
    receive "POST", start capture
    "HTTP/1.1 203 Hoe"CRLF
    "content-length: 0"CRLF
    CRLF
    receive "GET", end capture
    "HTTP/1.1 200 OK"CRLF
    CRLF
    sendcaptured
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}/foo});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    return $client->request (url => $url, body => "\xFE\x84", method => 'POST')->then (sub {
      return $client->request (url => $url);
    })->then (sub {
      my $res = $_[0];
      test {
        my $request = $res->body_bytes;
        $request =~ s/GET$//;
        unlike $request, qr{\x0AContent-Type:};
        like $request, qr{\x0AContent-Length: 2\x0D\x0A};
        like $request, qr{\x0D\x0A\x0D\x0A\xFE\x84$};
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 3, name => 'request options - body';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET", start capture
    "HTTP/1.1 203 Hoe"CRLF
    "content-length: 0"CRLF
    CRLF
    receive "GET", end capture
    "HTTP/1.1 200 OK"CRLF
    CRLF
    sendcaptured
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}/foo});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    return $client->request (url => $url, body => "\xFE\x84", method => 'GET')->then (sub {
      return $client->request (url => $url);
    })->then (sub {
      my $res = $_[0];
      test {
        my $request = $res->body_bytes;
        $request =~ s/GET$//;
        unlike $request, qr{\x0AContent-Type:};
        like $request, qr{\x0AContent-Length: 2\x0D\x0A};
        like $request, qr{\x0D\x0A\x0D\x0A\xFE\x84$};
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 3, name => 'request options - body';

test {
  my $c = shift;
  my $url = Web::URL->parse_string (qq{http://jogejoge.test/foo});
  my $client = Web::Transport::ConnectionClient->new_from_url ($url);
  $client->request (url => $url, body => "\x{4543}")->then (sub {
    test { ok 0 } $c;
  }, sub {
    my $err = $_[0];
    test {
      like $err->network_error_message, qr{^\|body\| is utf8-flagged};
    } $c;
  })->then (sub {
    return $client->close;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 1, name => 'request options - body';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET", start capture
    "HTTP/1.1 203 Hoe"CRLF
    "content-length: 0"CRLF
    CRLF
    receive "GET", end capture
    "HTTP/1.1 200 OK"CRLF
    CRLF
    sendcaptured
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}/foo});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    return $client->request (url => $url, bearer => "Fo+a/b==\x0D")->then (sub {
      return $client->request (url => $url);
    })->then (sub {
      my $res = $_[0];
      test {
        my $request = $res->body_bytes;
        $request =~ s/GET$//;
        like $request, qr{\x0AAuthorization: Bearer Fo\+a/b== \x0D\x0A};
        like $request, qr{\x0ACache-Control: no-store\x0D\x0A};
        like $request, qr{\x0APragma: no-cache\x0D\x0A};
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 3, name => 'request options - bearer';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET", start capture
    "HTTP/1.1 203 Hoe"CRLF
    "content-length: 0"CRLF
    CRLF
    receive "GET", end capture
    "HTTP/1.1 200 OK"CRLF
    CRLF
    sendcaptured
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}/foo});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    return $client->request (url => $url, basic_auth => ["t36 46343 :4yt324432gesageasee\xFE\x80", "geaga\x{400}gewaaa r:e:: e56363y43yg43434 cd 4"])->then (sub {
      return $client->request (url => $url);
    })->then (sub {
      my $res = $_[0];
      test {
        my $request = $res->body_bytes;
        $request =~ s/GET$//;
        like $request, qr{\x0AAuthorization: Basic dDM2IDQ2MzQzIDo0eXQzMjQ0MzJnZXNhZ2Vhc2Vlw77CgDpnZWFnYdCAZ2V3YWFhIHI6ZTo6IGU1NjM2M3k0M3lnNDM0MzQgY2QgNA==\x0D\x0A};
        like $request, qr{\x0ACache-Control: no-store\x0D\x0A};
        like $request, qr{\x0APragma: no-cache\x0D\x0A};
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 3, name => 'request options - basic';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET", start capture
    "HTTP/1.1 203 Hoe"CRLF
    "content-length: 0"CRLF
    CRLF
    receive "GET", end capture
    "HTTP/1.1 200 OK"CRLF
    CRLF
    sendcaptured
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}/foo?bar#baz});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    return $client->request (path => ['ac', '0', '', "\x{533}ab", "\xFE"])->then (sub {
      return $client->request (url => $url);
    })->then (sub {
      my $res = $_[0];
      test {
        my $request = $res->body_bytes;
        $request =~ s/GET$//;
        like $request, qr{^GET /foo/ac/0//%D4%B3ab/%C3%BE HTTP};
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'request - path';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET", start capture
    "HTTP/1.1 203 Hoe"CRLF
    "content-length: 0"CRLF
    CRLF
    receive "GET", end capture
    "HTTP/1.1 200 OK"CRLF
    CRLF
    sendcaptured
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}/foo?bar#baz});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    return $client->request (path => ['ac', '0', '', "\x{533}ab", "\xFE"], params => {hoge => "abc"})->then (sub {
      return $client->request (url => $url);
    })->then (sub {
      my $res = $_[0];
      test {
        my $request = $res->body_bytes;
        $request =~ s/GET$//;
        like $request, qr{^GET /foo/ac/0//%D4%B3ab/%C3%BE\?hoge=abc HTTP};
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'request - path and query';

for (
  [qq</hoge/\x{5000}>, q</hoge/%E5%80%80/ac/%E5%80%84>],
  [qq<hoge/\x{5000}>, q</hoge/%E5%80%80/ac/%E5%80%84>],
  [qq</>, q</ac/%E5%80%84>],
  [qq<>, q</ac/%E5%80%84>],
) {
  my ($path_prefix, $expected) = @$_;
  test {
    my $c = shift;
    server_as_cv (q{
      receive "GET", start capture
      "HTTP/1.1 203 Hoe"CRLF
      "content-length: 0"CRLF
      CRLF
      receive "GET", end capture
      "HTTP/1.1 200 OK"CRLF
      CRLF
      sendcaptured
      close
    })->cb (sub {
      my $server = $_[0]->recv;
      my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}/foo?bar#baz});
      my $client = Web::Transport::ConnectionClient->new_from_url ($url);
      return $client->request (path_prefix => $path_prefix, path => ['ac', "\x{5004}"])->then (sub {
        return $client->request (url => $url);
      })->then (sub {
        my $res = $_[0];
        test {
          my $request = $res->body_bytes;
          $request =~ s/GET$//;
          like $request, qr{^GET \Q$expected\E HTTP};
        } $c;
      })->then (sub{
        return $client->close;
      })->catch (sub {
        my $error = $_[0];
        test {
          is $error, undef, 'No exception';
        } $c;
      })->then (sub {
        done $c;
        undef $c;
      });
    });
  } n => 1, name => ['request - path_prefix', $path_prefix];
}

for (
  [qq<http://abc/def/xyzxs>],
  [qq<//abc/def/xyzxs>],
  [qq<https://abc/def/xyzxs>],
  [qq<ftp://abc/def/xyzxs>],
  [qq<about:blank>],
  [qq<http://hoge:[foo]>],
) {
  my ($path_prefix) = @$_;
  test {
    my $c = shift;
    server_as_cv (q{
      receive "GET", start capture
      "HTTP/1.1 203 Hoe"CRLF
      "content-length: 0"CRLF
      CRLF
      receive "GET", end capture
      "HTTP/1.1 200 OK"CRLF
      CRLF
      sendcaptured
      close
    })->cb (sub {
      my $server = $_[0]->recv;
      my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}/foo?bar#baz});
      my $client = Web::Transport::ConnectionClient->new_from_url ($url);
      return $client->request (path_prefix => $path_prefix, path => ['ac', "\x{5004}"])->then (sub {
        return $client->request (url => $url);
      })->then (sub {
        my $res = $_[0];
        test {
          ok 0;
        } $c;
      }, sub {
        my $error = $_[0];
        test {
          ok $error->is_network_error;
          is $error->network_error_message, "Bad |path_prefix|: |$path_prefix|";
          is ''.$error, "Network error: " . $error->network_error_message;
        } $c;
      })->then (sub{
        return $client->close;
      })->then (sub {
        done $c;
        undef $c;
      });
    });
  } n => 3, name => ['request - path_prefix', $path_prefix];
}

for (
  [[], q</f/oo/>],
  [['abc'], q</f/oo/abc>],
  [['', 'abc'], q</f/oo//abc>],
) {
  my ($input, $expected) = @$_;
  test {
    my $c = shift;
    server_as_cv (q{
      receive "GET", start capture
      "HTTP/1.1 203 Hoe"CRLF
      "content-length: 0"CRLF
      CRLF
      receive "GET", end capture
      "HTTP/1.1 200 OK"CRLF
      CRLF
      sendcaptured
      close
    })->cb (sub {
      my $server = $_[0]->recv;
      my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}/f/oo?bar#baz});
      my $client = Web::Transport::ConnectionClient->new_from_url ($url);
      return $client->request (path => $input)->then (sub {
        return $client->request (path => ['captured']);
      })->then (sub {
        my $res = $_[0];
        test {
          my $request = $res->body_bytes;
          $request =~ s/GET$//;
          like $request, qr{^GET \Q$expected\E HTTP};
        } $c;
      })->then (sub{
        return $client->close;
      })->catch (sub {
        my $error = $_[0];
        test {
          is $error, undef, 'No exception';
        } $c;
      })->then (sub {
        done $c;
        undef $c;
      });
    });
  } n => 1, name => ['request - path_prefix', @$input];

  test {
    my $c = shift;
    server_as_cv (q{
      receive "GET", start capture
      "HTTP/1.1 203 Hoe"CRLF
      "content-length: 0"CRLF
      CRLF
      receive "GET", end capture
      "HTTP/1.1 200 OK"CRLF
      CRLF
      sendcaptured
      close
    })->cb (sub {
      my $server = $_[0]->recv;
      my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}/f/oo/?bar#baz});
      my $client = Web::Transport::ConnectionClient->new_from_url ($url);
      return $client->request (path => $input)->then (sub {
        return $client->request (path => ['captured']);
      })->then (sub {
        my $res = $_[0];
        test {
          my $request = $res->body_bytes;
          $request =~ s/GET$//;
          like $request, qr{^GET \Q$expected\E HTTP};
        } $c;
      })->then (sub{
        return $client->close;
      })->catch (sub {
        my $error = $_[0];
        test {
          is $error, undef, 'No exception';
        } $c;
      })->then (sub {
        done $c;
        undef $c;
      });
    });
  } n => 1, name => ['request - path_prefix', @$input];
}

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET", start capture
    "HTTP/1.1 203 Hoe"CRLF
    "content-length: 0"CRLF
    CRLF
    receive "GET", end capture
    "HTTP/1.1 200 OK"CRLF
    CRLF
    sendcaptured
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    return $client->request (path => [], cookies => {})->then (sub {
      return $client->request (url => $url);
    })->then (sub {
      my $res = $_[0];
      test {
        my $request = $res->body_bytes;
        $request =~ s/GET$//;
        unlike $request, qr{[Cc]ookie};
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'request - cookie';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET", start capture
    "HTTP/1.1 203 Hoe"CRLF
    "content-length: 0"CRLF
    CRLF
    receive "GET", end capture
    "HTTP/1.1 200 OK"CRLF
    CRLF
    sendcaptured
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    return $client->request (path => [], cookies => {
      hoge => 'Fuga', abc => undef,
    })->then (sub {
      return $client->request (url => $url);
    })->then (sub {
      my $res = $_[0];
      test {
        my $request = $res->body_bytes;
        $request =~ s/GET$//;
        like $request, qr{\x0ACookie: hoge=Fuga\x0D\x0A};
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'request - cookie';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET", start capture
    "HTTP/1.1 203 Hoe"CRLF
    "content-length: 0"CRLF
    CRLF
    receive "GET", end capture
    "HTTP/1.1 200 OK"CRLF
    CRLF
    sendcaptured
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    return $client->request (path => [], cookies => {
      "\x{544} !=;" => "\x{1333}a=%\x09",
    })->then (sub {
      return $client->request (url => $url);
    })->then (sub {
      my $res = $_[0];
      test {
        my $request = $res->body_bytes;
        $request =~ s/GET$//;
        like $request, qr{\x0ACookie: %D5%84%20%21%3D%3B=%E1%8C%B3a%3D%25%09\x0D\x0A};
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'request - cookie';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET", start capture
    "HTTP/1.1 203 Hoe"CRLF
    "content-length: 0"CRLF
    CRLF
    receive "GET", end capture
    "HTTP/1.1 200 OK"CRLF
    CRLF
    sendcaptured
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    return $client->request (path => [], cookies => {
      "" => "",
    })->then (sub {
      return $client->request (url => $url);
    })->then (sub {
      my $res = $_[0];
      test {
        my $request = $res->body_bytes;
        $request =~ s/GET$//;
        like $request, qr{\x0ACookie: =\x0D\x0A};
        like $request, qr{\x0APragma: no-cache\x0D\x0A};
        like $request, qr{\x0ACache-Control: no-store\x0D\x0A};
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 3, name => 'request - cookie';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET", start capture
    "HTTP/1.1 203 Hoe"CRLF
    "content-length: 0"CRLF
    CRLF
    receive "GET", end capture
    "HTTP/1.1 200 OK"CRLF
    CRLF
    sendcaptured
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    return $client->request (path => [], cookies => {
      0, 0,
    }, headers => {Cookie => 'ab cd'})->then (sub {
      return $client->request (url => $url);
    })->then (sub {
      my $res = $_[0];
      test {
        my $request = $res->body_bytes;
        $request =~ s/GET$//;
        like $request, qr{\x0ACookie: ab cd\x0D\x0A};
        like $request, qr{\x0ACookie: 0=0\x0D\x0A};
        like $request, qr{ab cd.+0=0}s;
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 3, name => 'request - cookie';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET", start capture
    "HTTP/1.1 203 Hoe"CRLF
    "content-length: 0"CRLF
    CRLF
    receive "GET", end capture
    "HTTP/1.1 200 OK"CRLF
    CRLF
    sendcaptured
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    return $client->request (path => [], cookies => {
      foo => "abc", XYZ => "ddd",
    })->then (sub {
      return $client->request (url => $url);
    })->then (sub {
      my $res = $_[0];
      test {
        my $request = $res->body_bytes;
        $request =~ s/GET$//;
        ok $request =~ m{\x0ACookie: foo=abc; XYZ=ddd\x0D\x0A} ||
           $request =~ m{\x0ACookie: XYZ=ddd; foo=abc\x0D\x0A};
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 1, name => 'request - cookie';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET", start capture
    "HTTP/1.1 203 Hoe"CRLF
    "content-length: 0"CRLF
    CRLF
    receive "GET", end capture
    "HTTP/1.1 200 OK"CRLF
    CRLF
    sendcaptured
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    return $client->request (path => ['foo', 'ab ce'], params => {
      "XYZ\x{5000}" => "ddd\x{5003}",
    }, oauth1 => ["\x{5000}", "\x{5001}", "\x{5301}", "a\x{506}"])->then (sub {
      return $client->request (url => $url);
    })->then (sub {
      my $res = $_[0];
      test {
        my $request = $res->body_bytes;
        $request =~ s/GET$//;
        like $request, qr{GET /foo/ab%20ce\?XYZ%E5%80%80=ddd%E5%80%83 HTTP};
        like $request, qr{\x0AAuthorization: OAuth realm="", oauth_};
        unlike $request, qr{Content-Type};
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 3, name => 'request - oauth1';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET", start capture
    "HTTP/1.1 203 Hoe"CRLF
    "content-length: 0"CRLF
    CRLF
    receive "GET", end capture
    "HTTP/1.1 200 OK"CRLF
    CRLF
    sendcaptured
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    return $client->request (path => ['foo', 'ab ce'], params => {
      "XYZ\x{5000}" => "ddd\x{5003}",
    }, oauth1 => ["\x{5000}", "\x{5001}", "\x{5301}", "a\x{506}"], oauth1_container => 'query')->then (sub {
      return $client->request (url => $url);
    })->then (sub {
      my $res = $_[0];
      test {
        my $request = $res->body_bytes;
        $request =~ s/GET$//;
        like $request, qr{GET /foo/ab%20ce\?XYZ%E5%80%80=ddd%E5%80%83&oauth_};
        like $request, qr{\x0ACache-Control: no-store\x0D\x0A};
        like $request, qr{\x0APragma: no-cache\x0D\x0A};
        unlike $request, qr{Authorization};
        unlike $request, qr{Content-Type};
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 5, name => 'request - oauth1';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET", start capture
    "HTTP/1.1 203 Hoe"CRLF
    "content-length: 0"CRLF
    CRLF
    receive "GET", end capture
    "HTTP/1.1 200 OK"CRLF
    CRLF
    sendcaptured
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    return $client->request (path => ['foo', 'ab ce'], params => {
      "XYZ\x{5000}" => "ddd\x{5003}",
    }, oauth1 => ["\x{5000}", "\x{5001}", "\x{5301}", "a\x{506}"], oauth1_container => 'body')->then (sub {
      return $client->request (url => $url);
    })->then (sub {
      my $res = $_[0];
      test {
        my $request = $res->body_bytes;
        $request =~ s/GET$//;
        like $request, qr{GET /foo/ab%20ce\?XYZ%E5%80%80=ddd%E5%80%83 HTTP};
        like $request, qr{\x0ACache-Control: no-store\x0D\x0A};
        like $request, qr{\x0APragma: no-cache\x0D\x0A};
        unlike $request, qr{Authorization};
        like $request, qr{\x0AContent-Type: application/x-www-form-urlencoded\x0D\x0A};
        like $request, qr{&oauth_};
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 6, name => 'request - oauth1';

test {
  my $c = shift;
  server_as_cv (q{
    receive "POST", start capture
    "HTTP/1.1 203 Hoe"CRLF
    "content-length: 0"CRLF
    CRLF
    receive "GET", end capture
    "HTTP/1.1 200 OK"CRLF
    CRLF
    sendcaptured
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    return $client->request (path => ['foo', 'ab ce'], params => {
      "XYZ\x{5000}" => "ddd\x{5003}",
    }, oauth1 => ["\x{5000}", "\x{5001}", "\x{5301}", "a\x{506}"], method => 'POST', headers => {
      authorizatioN => 'Basic hogefuga',
    })->then (sub {
      return $client->request (url => $url);
    })->then (sub {
      my $res = $_[0];
      test {
        my $request = $res->body_bytes;
        $request =~ s/GET$//;
        like $request, qr{POST /foo/ab%20ce HTTP};
        like $request, qr{\x0ACache-Control: no-store\x0D\x0A};
        like $request, qr{\x0APragma: no-cache\x0D\x0A};
        unlike $request, qr{Authorization: OAuth};
        like $request, qr{\x0AContent-Type: application/x-www-form-urlencoded\x0D\x0A};
        like $request, qr{\x0AXYZ%E5%80%80=ddd%E5%80%83&oauth_};
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 6, name => 'request - oauth1';

test {
  my $c = shift;
  server_as_cv (q{
    receive "POST", start capture
    "HTTP/1.1 203 Hoe"CRLF
    "content-length: 0"CRLF
    CRLF
    receive "GET", end capture
    "HTTP/1.1 200 OK"CRLF
    CRLF
    sendcaptured
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    return $client->request (path => ['foo', 'ab ce'], params => {
      "XYZ\x{5000}" => "ddd\x{5003}",
    }, oauth1 => ["\x{5000}", "\x{5001}", "\x{5301}", "a\x{506}"], method => 'POST')->then (sub {
      return $client->request (url => $url);
    })->then (sub {
      my $res = $_[0];
      test {
        my $request = $res->body_bytes;
        $request =~ s/GET$//;
        like $request, qr{POST /foo/ab%20ce HTTP};
        like $request, qr{\x0ACache-Control: no-store\x0D\x0A};
        like $request, qr{\x0APragma: no-cache\x0D\x0A};
        like $request, qr{\x0AAuthorization: OAuth realm="", oauth_};
        like $request, qr{\x0AContent-Type: application/x-www-form-urlencoded\x0D\x0A};
        like $request, qr{\x0AXYZ%E5%80%80=ddd%E5%80%83(?!&)};
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 6, name => 'request - oauth1';

test {
  my $c = shift;
  server_as_cv (q{
    receive "POST", start capture
    "HTTP/1.1 203 Hoe"CRLF
    "content-length: 0"CRLF
    CRLF
    receive "GET", end capture
    "HTTP/1.1 200 OK"CRLF
    CRLF
    sendcaptured
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    return $client->request (path => ['foo', 'ab ce'], body => "abc", oauth1 => ["\x{5000}", "\x{5001}", "\x{5301}", "a\x{506}"], method => 'POST', headers => {
      authorizatioN => 'Basic hogefuga',
    })->then (sub {
      return $client->request (url => $url);
    })->then (sub {
      my $res = $_[0];
      test {
        my $request = $res->body_bytes;
        $request =~ s/GET$//;
        like $request, qr{POST /foo/ab%20ce\?oauth_};
        like $request, qr{\x0ACache-Control: no-store\x0D\x0A};
        like $request, qr{\x0APragma: no-cache\x0D\x0A};
        unlike $request, qr{Authorization: OAuth};
        unlike $request, qr{\x0AContent-Type: application/x-www-form-urlencoded\x0D\x0A};
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 5, name => 'request - oauth1';

test {
  my $c = shift;
  server_as_cv (q{
    receive "POST", start capture
    "HTTP/1.1 203 Hoe"CRLF
    "content-length: 0"CRLF
    CRLF
    receive "GET", end capture
    "HTTP/1.1 200 OK"CRLF
    CRLF
    sendcaptured
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    return $client->request (path => ['foo', 'ab ce'], body => "abc", oauth1 => ["\x{5000}", "\x{5001}", "\x{5301}", "a\x{506}"], method => 'POST', headers => {
      authorizatioN => 'Basic hogefuga',
      'content-Type' => 'text/plain; application/x-www-form-urlencoded',
    })->then (sub {
      return $client->request (url => $url);
    })->then (sub {
      my $res = $_[0];
      test {
        my $request = $res->body_bytes;
        $request =~ s/GET$//;
        like $request, qr{POST /foo/ab%20ce\?oauth_};
        like $request, qr{\x0ACache-Control: no-store\x0D\x0A};
        like $request, qr{\x0APragma: no-cache\x0D\x0A};
        unlike $request, qr{Authorization: OAuth};
        unlike $request, qr{\x0AContent-Type: application/x-www-form-urlencoded\x0D\x0A};
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 5, name => 'request - oauth1';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET", start capture
    "HTTP/1.1 203 Hoe"CRLF
    "content-length: 0"CRLF
    CRLF
    receive "GET", end capture
    "HTTP/1.1 200 OK"CRLF
    CRLF
    sendcaptured
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    return $client->request (path => ['foo', 'ab ce'], params => {
    }, files => {foo => undef})->then (sub {
      return $client->request (url => $url);
    })->then (sub {
      my $res = $_[0];
      test {
        my $request = $res->body_bytes;
        $request =~ s/GET$//;
        like $request, qr{GET /foo/ab%20ce HTTP};
        unlike $request, qr{\x0AContent-Type: multipart/form-data\x0D\x0A};
        like $request, qr{\x0AContent-Type: multipart/form-data; boundary=\w+\x0D\x0A};
        like $request, qr{\x0D\x0A--};
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 4, name => 'request - multipart/form-data';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET", start capture
    "HTTP/1.1 203 Hoe"CRLF
    "content-length: 0"CRLF
    CRLF
    receive "GET", end capture
    "HTTP/1.1 200 OK"CRLF
    CRLF
    sendcaptured
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    return $client->request (path => ['foo', 'ab ce'], params => {
      "\x{505}\x00" => "\x00\x0D\x{533}",
    }, files => {})->then (sub {
      return $client->request (url => $url);
    })->then (sub {
      my $res = $_[0];
      test {
        my $request = $res->body_bytes;
        $request =~ s/GET$//;
        like $request, qr{GET /foo/ab%20ce HTTP};
        unlike $request, qr{\x0AContent-Type: multipart/form-data\x0D\x0A};
        like $request, qr{\x0AContent-Type: multipart/form-data; boundary=\w+\x0D\x0A};
        like $request, qr{\x0D\x0A--};
        like $request, qr{\x0AContent-Disposition: form-data; name="\xD4\x85%00"\x0D\x0A\x0D\x0A\x00\x0D\xD4\xB3\x0D\x0A--};
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 5, name => 'request - multipart/form-data';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET", start capture
    "HTTP/1.1 203 Hoe"CRLF
    "content-length: 0"CRLF
    CRLF
    receive "GET", end capture
    "HTTP/1.1 200 OK"CRLF
    CRLF
    sendcaptured
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    return $client->request (path => ['foo', 'ab ce'], params => {
      "\x{505}\x00" => ["\x00\x0D\x{533}", ''],
    }, files => {
      "\x81\x91" => {body_ref => \"ab \x01\x02"},
    })->then (sub {
      return $client->request (url => $url);
    })->then (sub {
      my $res = $_[0];
      test {
        my $request = $res->body_bytes;
        $request =~ s/GET$//;
        like $request, qr{GET /foo/ab%20ce HTTP};
        unlike $request, qr{\x0AContent-Type: multipart/form-data\x0D\x0A};
        like $request, qr{\x0AContent-Type: multipart/form-data; boundary=\w+\x0D\x0A};
        like $request, qr{\x0D\x0A--};
        like $request, qr{\x0AContent-Disposition: form-data; name="\xD4\x85%00"\x0D\x0A\x0D\x0A\x00\x0D\xD4\xB3\x0D\x0A--.+\x0D\x0AContent-Disposition: form-data; name="\xD4\x85%00"\x0D\x0A\x0D\x0A\x0D\x0A--.+\x0D\x0AContent-Type: application/octet-stream\x0D\x0AContent-Disposition: form-data; name="\xC2\x81\xC2\x91"; filename=""\x0D\x0A\x0D\x0Aab \x01\x02\x0D\x0A--};
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 5, name => 'request - multipart/form-data';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET", start capture
    "HTTP/1.1 203 Hoe"CRLF
    "content-length: 0"CRLF
    CRLF
    receive "GET", end capture
    "HTTP/1.1 200 OK"CRLF
    CRLF
    sendcaptured
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    return $client->request (path => ['foo', 'ab ce'], files => {
      qq{\x81"} => {body_ref => \"", mime_filename => qq{\x0D\x0Aab/"c},
                    mime_type => "hoge\x0D\x0Afuga"},
    })->then (sub {
      return $client->request (url => $url);
    })->then (sub {
      my $res = $_[0];
      test {
        my $request = $res->body_bytes;
        $request =~ s/GET$//;
        like $request, qr{GET /foo/ab%20ce HTTP};
        unlike $request, qr{\x0AContent-Type: multipart/form-data\x0D\x0A};
        like $request, qr{\x0AContent-Type: multipart/form-data; boundary=\w+\x0D\x0A};
        like $request, qr{\x0D\x0A--};
        like $request, qr{\x0AContent-Type: hoge%0D%0Afuga\x0D\x0AContent-Disposition: form-data; name="\xC2\x81%22"; filename="%0D%0Aab/%22c"\x0D\x0A\x0D\x0A\x0D\x0A--};
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 5, name => 'request - multipart/form-data';

test {
  my $c = shift;
  my $url = Web::URL->parse_string (qq{http://jogejoge.test/foo});
  my $client = Web::Transport::ConnectionClient->new_from_url ($url);
  my $p = $client->request (url => $url, body => "abc", files => {
    foo => {body_ref => \""},
  });
  isa_ok $p, 'Promise';
  $p->then (sub {
    test { ok 0 } $c;
  }, sub {
    my $err = $_[0];
    test {
      is ''.$err, "Network error: Both |files| and |body| are specified";
    } $c;
  })->then (sub {
    return $client->close;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 2, name => 'request options - multipart/form-data';

test {
  my $c = shift;
  my $url = Web::URL->parse_string (qq{http://jogejoge.test/foo});
  my $client = Web::Transport::ConnectionClient->new_from_url ($url);
  my $p = $client->request (url => $url, files => {
    foo => {body_ref => \"\x{5000}"},
  });
  isa_ok $p, 'Promise';
  $p->then (sub {
    test { ok 0 } $c;
  }, sub {
    my $err = $_[0];
    test {
      is ''.$err, "Network error: File's |body_ref|'s value is utf8-flagged";
    } $c;
  })->then (sub {
    return $client->close;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 2, name => 'request options - multipart/form-data';

test {
  my $c = shift;
  my $url = Web::URL->parse_string (qq{http://jogejoge.test/foo});
  my $client = Web::Transport::ConnectionClient->new_from_url ($url);
  my $p = $client->request (url => $url, headers => {
    'content-type' => 'hoge',
  }, files => {
    foo => {body_ref => \""},
  });
  isa_ok $p, 'Promise';
  $p->then (sub {
    test { ok 0 } $c;
  }, sub {
    my $err = $_[0];
    test {
      is ''.$err, "Network error: Both |files| and |body| are specified";
    } $c;
  })->then (sub {
    return $client->close;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 2, name => 'request options - multipart/form-data';

test {
  my $c = shift;
  server_as_cv (q{
    receive "POST", start capture
    "HTTP/1.1 203 Hoe"CRLF
    CRLF
    receive CRLFCRLF, end capture
    sendcaptured
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    my $p = $client->request (url => $url, method => 'POST', params => {
      hoge => undef,
    });
    test {
      isa_ok $p, 'Promise';
    } $c;
    $p->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 203, $res;
        like $res->body_bytes, qr{Content-Length: 0\x0D\x0A};
      } $c;
    }, sub {
      my $error = $_[0];
      test { ok 0, $error } $c;
    })->then (sub {
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 3, name => 'request options - params with undef value only';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET /foo"
    receive "_S_", start capture
    receive "_E_", end capture
    "HTTP/1.0 203 Hoe"CRLF
    CRLF
    sendcaptured
    showcapturedlength
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $length = 5_000_000;
    my $url = Web::URL->parse_string (qq{http://host2.test:$server->{port}/foo});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    $client->resolver (bless {'host2.test' => '127.0.0.1'}, 'test::resolver1');
    my $data = '';
    my @alpha = ('0'..'9','A'..'Z','a'..'z');
    $data .= $alpha[rand @alpha] for 1..$length;
    return $client->request (url => $url, body => '_S_' . $data . '_E_')->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 203;
        is length $res->body_bytes, length ('_S_' . $data . '_E_');
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => 'large request data, plain HTTP over TCP';

test {
  my $c = shift;
  server_as_cv (q{
    starttls host=host2.test
    receive "GET /foo"
    receive "_S_", start capture
    receive "_E_", end capture
    "HTTP/1.0 203 Hoe"CRLF
    CRLF
    sendcaptured
    showcapturedlength
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $length = 5_000_000;
    my $url = Web::URL->parse_string (qq{https://host2.test:$server->{port}/foo});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    $client->resolver (bless {'host2.test' => '127.0.0.1'}, 'test::resolver1');
    $client->tls_options ({ca_file => Test::Certificates->ca_path ('cert.pem')});
    my $data = '';
    my @alpha = ('0'..'9','A'..'Z','a'..'z');
    $data .= $alpha[rand @alpha] for 1..$length;
    return $client->request (url => $url, body => '_S_' . $data . '_E_')->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 203;
        is length $res->body_bytes, length ('_S_' . $data . '_E_');
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => 'large request data, HTTPS';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET /"
    "HTTP/1.0 203 Hoe"CRLF
    CRLF
    "abc"
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}/});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    $client->request (url => $url, body => "x" x (1*1024*1024))->then (sub {
      my $res = $_[0];
      test {
        is $res->status, 203;
        is $res->body_bytes, "abc";
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => 'large request data rejected by server';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET /foo"
    "HTTP/1.0 203 Hoe"CRLF
    CRLF
    "abc"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}/});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    my $p = $client->request (url => $url);
    my $message = rand;
    (promised_sleep 1)->then (sub {
      return $client->abort (message => $message);
    })->then (sub {
      return $p;
    })->then (sub {
      my $res = $_[0];
      test {
        ok $res->is_network_error;
        is $res->network_error_message, $message;
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => 'abort';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET /foo"
    "HTTP/1.0 203 Hoe"CRLF
    CRLF
    "abc"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}/});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    my $p = $client->request (url => $url);
    my $p2 = $client->request (url => $url);
    my $message = rand;
    (promised_sleep 1)->then (sub {
      return $client->abort (message => $message);
    })->then (sub {
      return $p;
    })->then (sub {
      my $res = $_[0];
      test {
        ok $res->is_network_error;
        is $res->network_error_message, $message;
      } $c;
      return $p2;
    })->then (sub {
      my $res = $_[0];
      test {
        ok $res->is_network_error;
        is $res->network_error_message, $message;
      } $c;
    })->then (sub{
      return $client->close;
    })->catch (sub {
      my $error = $_[0];
      test {
        ok 0, 'No exception';
        is $error, undef, 'exception';
      } $c;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 4, name => 'abort 2';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET /foo"
    "HTTP/1.0 203 Hoe"CRLF
    CRLF
    "abc"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}/});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    my $p = $client->request (url => $url);
    my $message = rand;
    return $client->abort (message => $message)->then (sub {
      return $p;
    })->then (sub {
      my $res = $_[0];
      test {
        ok $res->is_network_error;
        is $res->network_error_message, $message;
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => 'abort';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET /foo"
    "HTTP/1.0 203 Hoe"CRLF
    CRLF
    "abc"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}/});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    my $p = $client->request (url => $url);
    (promised_sleep 1)->then (sub {
      return $client->abort;
    })->then (sub {
      return $p;
    })->then (sub {
      my $res = $_[0];
      test {
        ok $res->is_network_error;
        is $res->network_error_message, 'Aborted';
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => 'abort';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET /foo"
    "HTTP/1.0 203 Hoe"CRLF
    CRLF
    "abc"
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{https://$server->{host}:$server->{port}/});
    my $client = Web::Transport::ConnectionClient->new_from_url ($url);
    {
      package test::proxyForAbort4;
      use Promised::Flow;
      sub get_proxies_for_url {
        return promised_sleep (2)->then (sub {
          return [{protocol => 'tcp'}];
        });
      }
    }
    $client->proxy_manager (bless {}, 'test::proxyForAbort4');
    my $p = $client->request (url => $url);
    my $message = rand;
    (promised_sleep 1)->then (sub {
      return $client->abort (message => $message);
    })->then (sub {
      return $p;
    })->then (sub {
      my $res = $_[0];
      test {
        ok $res->is_network_error;
        is $res->network_error_message, $message;
      } $c;
    })->then (sub{
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => 'abort 4 - abort should work even when $client->abort is invoked during $client->{client}->connect is ongoing';

Test::Certificates->wait_create_cert;
run_tests;

=head1 LICENSE

Copyright 2016-2017 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
