use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->child ('t_deps/modules/*/lib');
use Web::URL;
use Web::Transport::TCPTransport;
use Web::Transport::ConnectionClient;
use Web::Transport::WSClient;
use Test::X1;
use Test::More;

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

my $Origin;
my $WSOrigin;
my $HandleRequestHeaders = {};
{
  use AnyEvent::Socket;
  use Web::Transport::HTTPServerConnection;
  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  $Origin = Web::URL->parse_string ("http://$host:$port");
  $WSOrigin = Web::URL->parse_string ("ws://$host:$port");

  my $cb = sub {
    my ($self, $type, $req) = @_;
    if ($type eq 'requestheaders') {
      my $handler = $HandleRequestHeaders->{$req->{target}};
      if (defined $handler) {
        $req->{body} = '';
        $handler->($self, $req);
      } else {
        die "No handler for |$req->{target}|";
      }
    } elsif ($type eq 'data') {
      $req->{body} .= $_[3];
    }
  }; # $cb

  our $server = tcp_server $host, $port, sub {
    Web::Transport::HTTPServerConnection->new_from_fh_and_host_and_port_and_cb
        ($_[0], $_[1], $_[2], $cb);
  };
}

test {
  my $c = shift;
  $HandleRequestHeaders->{'/hoge'} = sub {
    my ($self, $req) = @_;
    $req->send_response_headers
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga'],
        ]}, close => 1);
    $req->close_response;
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  $http->request (path => ['hoge'])->then (sub {
    my $res = $_[0];
    test {
      is $res->status, 201;
      is $res->status_text, 'OK';
      is $res->header ('Hoge'), 'Fuga';
      is $res->header ('Connection'), 'close';
      is $res->body_bytes, '';
    } $c;
  }, sub {
    test {
      ok 0;
    } $c;
  })->then (sub {
    return $http->close;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 5, name => 'no Content-Length, no body';

test {
  my $c = shift;
  $HandleRequestHeaders->{'/hoge2'} = sub {
    my ($self, $req) = @_;
    $req->send_response_headers
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga2'],
        ]}, close => 1);
    $req->send_response_data (\'abcde');
    $req->close_response;
    $req->close_response;
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  $http->request (path => ['hoge2'])->then (sub {
    my $res = $_[0];
    test {
      is $res->status, 201;
      is $res->status_text, 'OK';
      is $res->header ('Hoge'), 'Fuga2';
      is $res->header ('Connection'), 'close';
      is $res->body_bytes, 'abcde';
    } $c;
  }, sub {
    test {
      ok 0;
    } $c;
  })->then (sub {
    return $http->close;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 5, name => 'no Content-Length, with body, with explicit close=>1';

test {
  my $c = shift;
  $HandleRequestHeaders->{'/hoge3'} = sub {
    my ($self, $req) = @_;
    $req->send_response_headers
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga3'],
        ]});
    $req->send_response_data (\'');
    $req->send_response_data (\'abcde3');
    $req->close_response;
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  $http->request (path => ['hoge3'])->then (sub {
    my $res = $_[0];
    test {
      is $res->status, 201;
      is $res->status_text, 'OK';
      is $res->header ('Hoge'), 'Fuga3';
      is $res->header ('Connection'), undef;
      is $res->header ('Transfer-Encoding'), 'chunked';
      is $res->body_bytes, 'abcde3';
    } $c;
  }, sub {
    test {
      ok 0;
    } $c;
  })->then (sub {
    return $http->close;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 6, name => 'no Content-Length, with body, no explicit close=>1', timeout => 120;

test {
  my $c = shift;
  my $x;
  $HandleRequestHeaders->{'/hoge4'} = sub {
    my ($self, $req) = @_;
    $req->send_response_headers
        ({status => 304, status_text => 'OK', headers => [
          ['Hoge', 'Fuga4'],
        ]});
    eval {
      $req->send_response_data (\'abcde4');
    };
    $x = $@;
    $req->close_response;
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  $http->request (path => ['hoge4'])->then (sub {
    my $res = $_[0];
    test {
      is $res->status, 304;
      is $res->status_text, 'OK';
      is $res->header ('Hoge'), 'Fuga4';
      is $res->header ('Connection'), undef;
      is $res->body_bytes, '';
      like $x, qr{^Not writable for now at .+ line @{[__LINE__-15]}};
    } $c;
  }, sub {
    test {
      ok 0;
    } $c;
  })->then (sub {
    return $http->close;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 6, name => 'no payload body (304) but data';

test {
  my $c = shift;
  $HandleRequestHeaders->{'/hoge5'} = sub {
    my ($self, $req) = @_;
    $req->send_response_headers
        ({status => 304, status_text => 'OK', headers => [
          ['Hoge', 'Fuga5'],
        ]});
    $req->close_response;
  };
  $HandleRequestHeaders->{'/hoge6'} = sub {
    my ($self, $req) = @_;
    $req->send_response_headers
        ({status => 200, status_text => 'OK', headers => [
          ['Hoge', 'Fuga6'],
        ]});
    $req->send_response_data (\'abcde6');
    $req->close_response;
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  $http->request (path => ['hoge5'])->then (sub {
    my $res = $_[0];
    test {
      is $res->status, 304;
      is $res->status_text, 'OK';
      is $res->header ('Hoge'), 'Fuga5';
      is $res->header ('Connection'), undef;
      is $res->body_bytes, '';
    } $c;
    return $http->request (path => ['hoge6'], headers => {connection => 'close'});
  })->then (sub {
    my $res = $_[0];
    test {
      is $res->status, 200;
      is $res->status_text, 'OK';
      is $res->header ('Hoge'), 'Fuga6';
      is $res->header ('Connection'), 'close';
      is $res->body_bytes, 'abcde6';
    } $c;
  })->catch (sub {
    test {
      ok 0;
    } $c;
  })->then (sub {
    return $http->close;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 10, name => '304 then 200 with data';

test {
  my $c = shift;
  my $x;
  $HandleRequestHeaders->{'/hoge7'} = sub {
    my ($self, $req) = @_;
    $req->send_response_headers
        ({status => 200, status_text => 'OK', headers => [
          ['Hoge', 'Fuga7'],
        ]});
    eval {
      $req->send_response_data (\'abcde7');
    };
    $x = $@;
    $req->close_response;
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  $http->request (path => ['hoge7'], method => 'HEAD')->then (sub {
    my $res = $_[0];
    test {
      is $res->status, 200;
      is $res->status_text, 'OK';
      is $res->header ('Hoge'), 'Fuga7';
      is $res->header ('Connection'), undef;
      is $res->body_bytes, '';
      like $x, qr{^Not writable for now at .+ line @{[__LINE__-15]}};
    } $c;
  }, sub {
    test {
      ok 0;
    } $c;
  })->then (sub {
    return $http->close;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 6, name => 'no payload body (HEAD) but data';

test {
  my $c = shift;
  my $x;
  $HandleRequestHeaders->{'/hoge8'} = sub {
    my ($self, $req) = @_;
    $req->send_response_headers
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga8'],
        ]}, content_length => 12);
    $req->send_response_data (\'abcde8');
    $req->send_response_data (\'');
    $req->send_response_data (\'abcde9');
    eval {
      $req->send_response_data (\'abcde10');
    };
    $x = $@;
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  $http->request (path => ['hoge8'])->then (sub {
    my $res = $_[0];
    test {
      is $res->status, 201;
      is $res->status_text, 'OK';
      is $res->header ('Hoge'), 'Fuga8';
      is $res->header ('Connection'), undef;
      is $res->body_bytes, 'abcde8abcde9';
      like $x, qr{^Not writable for now at .+ line @{[__LINE__-14]}};
    } $c;
  }, sub {
    test {
      ok 0;
    } $c;
  })->then (sub {
    return $http->close;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 6, name => 'with Content-Length';

test {
  my $c = shift;
  my $x;
  $HandleRequestHeaders->{'/hoge11'} = sub {
    my ($self, $req) = @_;
    $req->send_response_headers
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga11'],
        ]}, content_length => 12);
    $req->send_response_data (\'abcd11');
    eval {
      $req->send_response_data (\'abcde12');
    };
    $req->send_response_data (\'abcd13');
    $x = $@;
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  $http->request (path => ['hoge11'])->then (sub {
    my $res = $_[0];
    test {
      is $res->status, 201;
      is $res->status_text, 'OK';
      is $res->header ('Hoge'), 'Fuga11';
      is $res->header ('Connection'), undef;
      is $res->body_bytes, 'abcd11abcd13';
      like $x, qr{^Data too long \(given 7 bytes whereas only 6 bytes allowed\) at .+ line @{[__LINE__-15]}};
    } $c;
  }, sub {
    test {
      ok 0;
    } $c;
  })->then (sub {
    return $http->close;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 6, name => 'with Content-Length';

test {
  my $c = shift;
  $HandleRequestHeaders->{'/hoge14'} = sub {
    my ($self, $req) = @_;
    $req->send_response_headers
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga14'],
        ]}, content_length => 8);
    $req->send_response_data (\'abcdef14');
  };
  $HandleRequestHeaders->{'/hoge15'} = sub {
    my ($self, $req) = @_;
    $req->send_response_headers
        ({status => 202, status_text => 'OK', headers => [
          ['Hoge', 'Fuga15'],
        ]}, content_length => 10);
    $req->send_response_data (\'abcdefgh15');
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  Promise->all ([
    $http->request (path => ['hoge14']),
    $http->request (path => ['hoge15']),
  ])->then (sub {
    my $res1 = $_[0]->[0];
    my $res2 = $_[0]->[1];
    test {
      is $res1->status, 201;
      is $res1->status_text, 'OK';
      is $res1->header ('Hoge'), 'Fuga14';
      is $res1->header ('Connection'), undef;
      is $res1->header ('Content-Length'), '8';
      is $res1->body_bytes, 'abcdef14';
      is $res2->status, 202;
      is $res2->status_text, 'OK';
      is $res2->header ('Hoge'), 'Fuga15';
      is $res2->header ('Connection'), undef;
      is $res2->header ('Content-Length'), '10';
      is $res2->body_bytes, 'abcdefgh15';
    } $c;
  }, sub {
    test {
      ok 0;
    } $c;
  })->then (sub {
    return $http->close;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 12, name => 'with Content-Length';

test {
  my $c = shift;
  my $x;
  $HandleRequestHeaders->{'/hoge16'} = sub {
    my ($self, $req) = @_;
    $req->send_response_headers
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga16'],
        ]}, content_length => 0);
    eval {
      $req->send_response_data (\'abcde16');
    };
    $x = $@;
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  $http->request (path => ['hoge16'])->then (sub {
    my $res = $_[0];
    test {
      is $res->status, 201;
      is $res->status_text, 'OK';
      is $res->header ('Hoge'), 'Fuga16';
      is $res->header ('Connection'), undef;
      is $res->header ('Content-Length'), '0';
      is $res->body_bytes, '';
      like $x, qr{^Not writable for now at .+ line @{[__LINE__-15]}};
    } $c;
  }, sub {
    test {
      ok 0;
    } $c;
  })->then (sub {
    return $http->close;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 7, name => 'with Content-Length: 0';

test {
  my $c = shift;
  $HandleRequestHeaders->{'/hoge17'} = sub {
    my ($self, $req) = @_;
    $req->send_response_headers
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga17'],
        ]}, content_length => 10);
    $req->send_response_data (\'abc17');
    $req->close_response;
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  $http->request (path => ['hoge17'])->then (sub {
    my $res = $_[0];
    test {
      ok $res->is_network_error;
      is $res->network_error_message, 'Connection truncated';
    } $c;
  }, sub {
    test {
      ok 0;
    } $c;
  })->then (sub {
    return $http->close;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 2, name => 'closed before data is sent enough';

sub rawtcp ($) {
  my $input = $_[0];
  my $tcp = Web::Transport::TCPTransport->new (host => $Origin->host, port => $Origin->port);
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
} # rawtcp

test {
  my $c = shift;
  $HandleRequestHeaders->{'/hoge18'} = sub {
    my ($self, $req) = @_;
    $req->send_response_headers
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga18'],
        ]}, content_length => 5);
    $req->send_response_data (\'abc18');
  };

  rawtcp (qq{GET /hoge18\x0D\x0A})->then (sub {
    my $data = $_[0];
    test {
      is $data, q{abc18};
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 1, name => 'HTTP/0.9 response with data';

test {
  my $c = shift;
  $HandleRequestHeaders->{'/hoge19'} = sub {
    my ($self, $req) = @_;
    $req->send_response_headers
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga19'],
        ]});
    $req->send_response_data (\'abc19');
    $req->close_response;
  };

  rawtcp (qq{GET /hoge19\x0D\x0A})->then (sub {
    my $data = $_[0];
    test {
      is $data, q{abc19};
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 1, name => 'HTTP/0.9 response with data, without length';

test {
  my $c = shift;
  $HandleRequestHeaders->{'/hoge20'} = sub {
    my ($self, $req) = @_;
    $req->send_response_headers
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga19'],
        ]});
    $req->send_response_data (\'abc19');
    $req->close_response;
  };

  rawtcp (qq{HEAD /hoge20\x0D\x0A})->then (sub {
    my $data = $_[0];
    test {
      is $data, q{<!DOCTYPE html><html>
<head><title>400 Bad Request</title></head>
<body>400 Bad Request</body></html>
};
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 1, name => 'HTTP/0.9 HEAD request';

test {
  my $c = shift;
  $HandleRequestHeaders->{'/hoge21'} = sub {
    my ($self, $req) = @_;
    $req->send_response_headers
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga21'],
        ]});
    $req->send_response_data (\'abc21');
    $req->send_response_data (\'abc');
    $req->send_response_data (\'xyz');
    $req->close_response;
  };

  rawtcp (qq{GET /hoge21\x0D\x0A})->then (sub {
    my $data = $_[0];
    test {
      is $data, q{abc21abcxyz};
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 1, name => 'HTTP/0.9 response with data';

test {
  my $c = shift;
  $HandleRequestHeaders->{'/hoge22'} = sub {
    my ($self, $req) = @_;
    $req->send_response_headers
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga22'],
        ]}, content_length => 10);
    $req->send_response_data (\'abc22');
    $req->close_response;
  };

  rawtcp (qq{GET /hoge22 HTTP/1.0\x0D\x0AHost: @{[$Origin->hostport]}\x0D\x0A\x0D\x0A})->then (sub {
    my $data = $_[0];
    test {
      like $data, qr{\AHTTP/1.1 201 OK[\s\S]*
Connection: close\x0D
Content-Length: 10\x0D
Hoge: Fuga22\x0D
\x0D
abc22\z};
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 1, name => 'HTTP/1.0 early closure';

test {
  my $c = shift;
  my $x;
  $HandleRequestHeaders->{'/hoge23'} = sub {
    my ($self, $req) = @_;
    $req->send_response_headers
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga23'],
        ]}, close => 1);
    $req->send_response_data (\'abc23');
    $req->close_response;
    eval {
      $req->send_response_data (\'xyz');
    };
    $x = $@;
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  $http->request (path => ['hoge23'])->then (sub {
    my $res = $_[0];
    test {
      is $res->status, 201;
      is $res->status_text, 'OK';
      is $res->header ('Hoge'), 'Fuga23';
      is $res->header ('Connection'), 'close';
      is $res->body_bytes, 'abc23';
      like $x, qr{^Not writable for now at .+ line @{[__LINE__-14]}};
    } $c;
  }, sub {
    test {
      ok 0;
    } $c;
  })->then (sub {
    return $http->close;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 6, name => 'send after close not allowed';

test {
  my $c = shift;
  my $x;
  $HandleRequestHeaders->{'/hoge24'} = sub {
    my ($self, $req) = @_;
    $req->send_response_headers
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga24'],
        ]}, content_length => 12);
    $req->send_response_data (\'abcd24');
    eval {
      $req->send_response_data (\"\x{5000}");
    };
    $req->send_response_data (\'abcdee');
    $x = $@;
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  $http->request (path => ['hoge24'])->then (sub {
    my $res = $_[0];
    test {
      is $res->status, 201;
      is $res->status_text, 'OK';
      is $res->header ('Hoge'), 'Fuga24';
      is $res->header ('Connection'), undef;
      is $res->body_bytes, 'abcd24abcdee';
      like $x, qr{^Data is utf8-flagged at .+ line @{[__LINE__-15]}};
    } $c;
  }, sub {
    test {
      ok 0;
    } $c;
  })->then (sub {
    return $http->close;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 6, name => 'send utf8 data';

test {
  my $c = shift;
  my $x;
  $HandleRequestHeaders->{'/hoge25'} = sub {
    my ($self, $req) = @_;
    $req->send_response_headers
        ({status => 304, status_text => 'OK', headers => [
          ['Hoge', 'Fuga25'],
        ]}, content_length => 5);
    eval {
      $req->send_response_data (\'abcde');
    };
    $x = $@;
    $req->close_response;
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  $http->request (path => ['hoge25'])->then (sub {
    my $res = $_[0];
    test {
      is $res->status, 304;
      is $res->status_text, 'OK';
      is $res->header ('Hoge'), 'Fuga25';
      is $res->header ('Connection'), undef;
      is $res->header ('Content-Length'), '5';
      is $res->body_bytes, '';
      like $x, qr{^Not writable for now at .+ line @{[__LINE__-16]}};
    } $c;
  }, sub {
    test {
      ok 0;
    } $c;
  })->then (sub {
    return $http->close;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 7, name => '304 with Content-Length';

test {
  my $c = shift;
  my $x;
  $HandleRequestHeaders->{'/hoge26'} = sub {
    my ($self, $req) = @_;
    $req->send_response_headers
        ({status => 304, status_text => 'OK', headers => [
          ['Hoge', 'Fuga26'],
        ]}, content_length => 0);
    eval {
      $req->send_response_data (\'abcde');
    };
    $x = $@;
    $req->close_response;
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  $http->request (path => ['hoge26'])->then (sub {
    my $res = $_[0];
    test {
      is $res->status, 304;
      is $res->status_text, 'OK';
      is $res->header ('Hoge'), 'Fuga26';
      is $res->header ('Connection'), undef;
      is $res->header ('Content-Length'), '0';
      is $res->body_bytes, '';
      like $x, qr{^Not writable for now at .+ line @{[__LINE__-16]}};
    } $c;
  }, sub {
    test {
      ok 0;
    } $c;
  })->then (sub {
    return $http->close;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 7, name => '304 with Content-Length=0';

test {
  my $c = shift;
  $HandleRequestHeaders->{'/hoge27'} = sub {
    my ($self, $req) = @_;
    $req->send_response_headers
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga27'],
        ]});
    $req->send_response_data (\'abc');
    $req->send_response_data (\'');
    $req->send_response_data (\'xyz');
    $req->close_response;
  };

  rawtcp (qq{GET /hoge27 HTTP/1.0\x0D\x0AHost: @{[$Origin->hostport]}\x0D\x0A\x0D\x0A})->then (sub {
    my $data = $_[0];
    test {
      like $data, qr{\AHTTP/1.1 201 OK[\s\S]*
Connection: close\x0D
Hoge: Fuga27\x0D
\x0D
abcxyz\z};
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 1, name => 'HTTP/1.0 response with data without Content-Length';

test {
  my $c = shift;
  $HandleRequestHeaders->{'/hoge28'} = sub {
    my ($self, $req) = @_;
    $req->send_response_headers
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga28'],
        ]});
    $req->send_response_data (\'abc');
    $req->send_response_data (\'');
    $req->send_response_data (\'xyz');
    $req->close_response;
  };

  rawtcp (qq{CONNECT /hoge28 HTTP/1.0\x0D\x0Aconnection:keep-alive\x0D\x0AHost: @{[$Origin->hostport]}\x0D\x0A\x0D\x0A})->then (sub {
    my $data = $_[0];
    test {
      like $data, qr{\AHTTP/1.1 201 OK[\s\S]*
Connection: keep-alive\x0D
Hoge: Fuga28\x0D
\x0D
abcxyz\z};
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 1, name => 'CONNECT HTTP/1.0';

test {
  my $c = shift;
  $HandleRequestHeaders->{'/hoge29'} = sub {
    my ($self, $req) = @_;
    $req->send_response_headers
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga29'],
        ]});
    $req->send_response_data (\'abc');
    $req->send_response_data (\'');
    $req->send_response_data (\'xyz');
    $req->close_response;
  };

  rawtcp (qq{CONNECT /hoge29 HTTP/1.1\x0D\x0AHost: @{[$Origin->hostport]}\x0D\x0A\x0D\x0A})->then (sub {
    my $data = $_[0];
    test {
      like $data, qr{\AHTTP/1.1 201 OK[\s\S]*
Hoge: Fuga29\x0D
\x0D
abcxyz\z};
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 1, name => 'CONNECT HTTP/1.1';

test {
  my $c = shift;
  my $serverreq;
  $HandleRequestHeaders->{'/hoge30'} = sub {
    my ($self, $req) = @_;
    $req->send_response_headers
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga30'],
        ]});
    $req->send_response_data (\'abc');
    $req->send_response_data (\'');
    $req->send_response_data (\'xyz');
    $req->close_response;
    $serverreq = $req;
  };

  rawtcp (qq{CONNECT /hoge30 HTTP/1.1\x0D\x0AHost: @{[$Origin->hostport]}\x0D\x0Acontent-length:3\x0D\x0A\x0D\x0Aabcabc})->then (sub {
    my $data = $_[0];
    test {
      like $data, qr{\AHTTP/1.1 201 OK[\s\S]*
Hoge: Fuga30\x0D
\x0D
abcxyz\z};
      is $serverreq->{body}, 'abcabc';
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 2, name => 'CONNECT HTTP/1.1';

test {
  my $c = shift;
  my $serverreq;
  $HandleRequestHeaders->{'/hoge31'} = sub {
    my ($self, $req) = @_;
    $req->send_response_headers
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga31'],
        ]});
    $req->send_response_data (\'abc');
    $req->send_response_data (\'');
    $req->send_response_data (\'xyz');
    $req->close_response;
    $serverreq = $req;
  };

  rawtcp (qq{CONNECT /hoge31 HTTP/1.1\x0D\x0AHost: @{[$Origin->hostport]}\x0D\x0Acontent-length:3ab\x0D\x0A\x0D\x0Aabcabc})->then (sub {
    my $data = $_[0];
    test {
      like $data, qr{\AHTTP/1.1 400 Bad Request[\s\S]*
Connection: close\x0D
Content-Length: 102\x0D
Content-Type: text/html; charset=utf-8\x0D
\x0D
<!DOCTYPE html><html>
<head><title>400 Bad Request</title></head>
<body>400 Bad Request</body></html>
\z};
      is $serverreq->{body}, undef;
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 2, name => 'CONNECT HTTP/1.1 bad Content-Length';

test {
  my $c = shift;
  my $serverreq;
  $HandleRequestHeaders->{'/hoge32'} = sub {
    my ($self, $req) = @_;
    $req->send_response_headers
        ({status => 200, status_text => 'OK', headers => [
          ['Hoge', 'Fuga32'],
        ]});
    $req->send_response_data (\'abc');
    $req->send_response_data (\'');
    $req->send_response_data (\'xyz');
    $req->close_response;
    $serverreq = $req;
  };

  Web::Transport::WSClient->new (
    url => Web::URL->parse_string (q</hoge32>, $WSOrigin),
    cb => sub {
      test {
        ok 0;
      } $c;
    },
  )->then (sub {
    test {
      is $serverreq->{body}, '';
    } $c;
    done $c;
    undef $c;
  });
} n => 1, name => 'WS not handshake-able endpoint';

test {
  my $c = shift;
  my $serverreq;
  $HandleRequestHeaders->{'/hoge33'} = sub {
    my ($self, $req) = @_;
    $req->send_response_headers
        ({status => 101, status_text => 'OK', headers => [
          ['Hoge', 'Fuga33'],
        ]});
    $req->close_response (status => 5678);
    $serverreq = $req;
  };

  Web::Transport::WSClient->new (
    url => Web::URL->parse_string (q</hoge33>, $WSOrigin),
    cb => sub {
      test {
        ok 1;
      } $c;
    },
  )->then (sub {
    my $res = $_[0];
    test {
      is $serverreq->{body}, '';
      ok ! $res->is_network_error;
      ok $res->ws_closed_cleanly;
      is $res->ws_code, 5678;
      is $res->ws_reason, '';
    } $c;
    done $c;
    undef $c;
  });
} n => 6, name => 'WS handshaked';

test {
  my $c = shift;
  my $path = rand;
  my $invoked;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $req->send_response_headers
        ({status => 201, status_text => 'OK'}, content_length => 0);
    $req->close_response;
    $invoked = 1;
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  $http->request (path => [$path], headers => {
    Upgrade => 'websocket',
  })->then (sub {
    my $res = $_[0];
    test {
      ok ! $invoked;
      is $res->status, 400;
      is $res->status_text, 'Bad Request';
      is $res->header ('Connection'), 'close';
      is $res->header ('Content-Type'), 'text/html; charset=utf-8';
      is $res->body_bytes, q{<!DOCTYPE html><html>
<head><title>400 Bad Request</title></head>
<body>400 Bad Request</body></html>
};
    } $c;
  }, sub {
    test {
      ok 0;
    } $c;
  })->then (sub {
    return $http->close;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 6, name => 'WS handshake error - Upgrade: websocket only';

test {
  my $c = shift;
  my $path = rand;
  my $invoked;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $req->send_response_headers
        ({status => 201, status_text => 'OK'}, content_length => 0);
    $req->close_response;
    $invoked = 1;
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  $http->request (path => [$path], headers => {
    Upgrade => 'websocket',
    Connection => 'upgrade',
    'Sec-WebSocket-Version' => 13,
    'Sec-WebSocket-Key' => 'abcdef1234567890ABCDEF==',
  })->then (sub {
    my $res = $_[0];
    test {
      ok $invoked;
      is $res->status, 201;
      is $res->status_text, 'OK';
      is $res->header ('Connection'), 'close';
      is $res->body_bytes, q{};
    } $c;
  }, sub {
    test {
      ok 0;
    } $c;
  })->then (sub {
    return $http->close;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 5, name => 'WS handshake - not handshake response';

test {
  my $c = shift;
  my $path = rand;
  my $invoked;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $req->send_response_headers
        ({status => 201, status_text => 'OK'}, content_length => 0);
    $req->close_response;
    $invoked = 1;
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  $http->request (path => [$path], headers => {
    Upgrade => 'websocket',
    Connection => 'upgrade',
    'Sec-WebSocket-Version' => 13,
    'Sec-WebSocket-Key' => 'abcdef1234567890ABCDEF==',
    'Content-Length' => 42,
  })->then (sub {
    my $res = $_[0];
    test {
      ok $invoked;
      is $res->status, 201;
      is $res->status_text, 'OK';
      is $res->header ('Connection'), undef;
      is $res->body_bytes, q{};
    } $c;
  }, sub {
    test {
      ok 0;
    } $c;
  })->then (sub {
    return $http->close;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 5, name => 'WS handshake with Content-Length - not handshake response (no request body, timeout)', timeout => 120;

test {
  my $c = shift;
  my $path = rand;
  my $invoked;
  my $serverreq;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $req->send_response_headers
        ({status => 201, status_text => 'OK'}, content_length => 0, close => 1);
    $req->close_response;
    $serverreq = $req;
    $invoked = 1;
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  $http->request (path => [$path], headers => {
    Upgrade => 'websocket',
    Connection => 'upgrade',
    'Sec-WebSocket-Version' => 13,
    'Sec-WebSocket-Key' => 'abcdef1234567890ABCDEF==',
  }, body => "x" x 42)->then (sub {
    my $res = $_[0];
    test {
      ok $invoked;
      is $res->status, 201;
      is $res->status_text, 'OK';
      is $res->header ('Connection'), 'close';
      is $res->body_bytes, q{};
      is $serverreq->{body}, q{x} x 42;
    } $c;
  }, sub {
    my $error = $_[0];
    test {
      is $error, undef, 'exception';
    } $c;
  })->then (sub {
    return $http->close;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 6, name => 'WS handshake with Content-Length - not handshake response', timeout => 120;

test {
  my $c = shift;
  my $path = rand;
  my $invoked;
  my $serverreq;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $req->send_response_headers
        ({status => 201, status_text => 'OK'}, content_length => 0, close => 1);
    $req->close_response;
    $serverreq = $req;
    $invoked = 1;
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  $http->request (path => [$path], headers => {
    Upgrade => 'websocket',
    Connection => 'upgrade',
    'Sec-WebSocket-Version' => 13,
    'Sec-WebSocket-Key' => 'abcdef1234567890ABCDEF==',
  }, body => "")->then (sub {
    my $res = $_[0];
    test {
      ok $invoked;
      is $res->status, 201;
      is $res->status_text, 'OK';
      is $res->header ('Connection'), 'close';
      is $res->body_bytes, q{};
      is $serverreq->{body}, q{};
    } $c;
  }, sub {
    my $error = $_[0];
    test {
      is $error, undef, 'exception';
    } $c;
  })->then (sub {
    return $http->close;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 6, name => 'WS handshake with Content-Length:0 - not handshake response', timeout => 120;

test {
  my $c = shift;
  my $path = rand;
  my $invoked;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $req->send_response_headers
        ({status => 201, status_text => 'OK'}, content_length => 0);
    $req->close_response;
    $invoked = 1;
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  $http->request (path => [$path], headers => {
    Upgrade => 'websocket',
    Connection => 'upgrade',
    'Sec-WebSocket-Version' => 14,
    'Sec-WebSocket-Key' => 'abcdef1234567890ABCDEF==',
  })->then (sub {
    my $res = $_[0];
    test {
      ok ! $invoked;
      is $res->status, 426;
      is $res->status_text, 'Upgrade Required';
      is $res->header ('Connection'), 'close';
      is $res->header ('Upgrade'), 'websocket';
      is $res->header ('Sec-WebSocket-Version'), '13';
      is $res->header ('Content-Type'), 'text/html; charset=utf-8';
      is $res->body_bytes, q{<!DOCTYPE html><html>
<head><title>426 Upgrade Required</title></head>
<body>426 Upgrade Required</body></html>
};
    } $c;
  }, sub {
    test {
      ok 0;
    } $c;
  })->then (sub {
    return $http->close;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 8, name => 'WS handshake error - Bad version';

test {
  my $c = shift;
  my $path = rand;
  my $invoked;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $req->send_response_headers
        ({status => 201, status_text => 'OK'}, content_length => 0);
    $req->close_response;
    $invoked = 1;
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  $http->request (path => [$path], headers => {
    Upgrade => 'websocket',
    Connection => 'upgrade',
    'Sec-WebSocket-Version' => 13,
    'Sec-WebSocket-Key' => 'abcdef1234567890ABCDEF',
  })->then (sub {
    my $res = $_[0];
    test {
      ok ! $invoked;
      is $res->status, 400;
      is $res->status_text, 'Bad Request';
      is $res->header ('Connection'), 'close';
      is $res->header ('Content-Type'), 'text/html; charset=utf-8';
      is $res->body_bytes, q{<!DOCTYPE html><html>
<head><title>400 Bad Request</title></head>
<body>400 Bad Request</body></html>
};
    } $c;
  }, sub {
    test {
      ok 0;
    } $c;
  })->then (sub {
    return $http->close;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 6, name => 'WS handshake error - Bad key';

test {
  my $c = shift;
  my $path = rand;
  my $invoked;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $req->send_response_headers
        ({status => 201, status_text => 'OK'}, content_length => 0);
    $req->close_response;
    $invoked = 1;
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  $http->request (path => [$path], headers => {
    Upgrade => 'websocket2',
    Connection => 'upgrade',
    'Sec-WebSocket-Version' => 13,
    'Sec-WebSocket-Key' => 'abcdef1234567890ABCDEF==',
  })->then (sub {
    my $res = $_[0];
    test {
      ok ! $invoked;
      is $res->status, 400;
      is $res->status_text, 'Bad Request';
      is $res->header ('Connection'), 'close';
      is $res->header ('Content-Type'), 'text/html; charset=utf-8';
      is $res->body_bytes, q{<!DOCTYPE html><html>
<head><title>400 Bad Request</title></head>
<body>400 Bad Request</body></html>
};
    } $c;
  }, sub {
    test {
      ok 0;
    } $c;
  })->then (sub {
    return $http->close;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 6, name => 'WS handshake error - Bad upgrade';

test {
  my $c = shift;
  my $path = rand;
  my $invoked;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $req->send_response_headers
        ({status => 201, status_text => 'OK'}, content_length => 0);
    $req->close_response;
    $invoked = 1;
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  $http->request (path => [$path], headers => {
    Upgrade => 'websocket',
    'Sec-WebSocket-Version' => 13,
    'Sec-WebSocket-Key' => 'abcdef1234567890ABCDEF==',
  })->then (sub {
    my $res = $_[0];
    test {
      ok ! $invoked;
      is $res->status, 400;
      is $res->status_text, 'Bad Request';
      is $res->header ('Connection'), 'close';
      is $res->header ('Content-Type'), 'text/html; charset=utf-8';
      is $res->body_bytes, q{<!DOCTYPE html><html>
<head><title>400 Bad Request</title></head>
<body>400 Bad Request</body></html>
};
    } $c;
  }, sub {
    test {
      ok 0;
    } $c;
  })->then (sub {
    return $http->close;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 6, name => 'WS handshake error - No connection:upgrade';

test {
  my $c = shift;
  my $path = rand;
  my $invoked;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $req->send_response_headers
        ({status => 201, status_text => 'OK'}, content_length => 0);
    $req->close_response;
    $invoked = 1;
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  $http->request (path => [$path], headers => {
    Upgrade => 'websocket',
    Connection => 'upgrade',
    'Sec-WebSocket-Version' => 13,
    'Sec-WebSocket-Key' => ['abcdef1234567890ABCDEF==','abcdef1234567890ABCDEF=='],
  })->then (sub {
    my $res = $_[0];
    test {
      ok ! $invoked;
      is $res->status, 400;
      is $res->status_text, 'Bad Request';
      is $res->header ('Connection'), 'close';
      is $res->header ('Content-Type'), 'text/html; charset=utf-8';
      is $res->body_bytes, q{<!DOCTYPE html><html>
<head><title>400 Bad Request</title></head>
<body>400 Bad Request</body></html>
};
    } $c;
  }, sub {
    test {
      ok 0;
    } $c;
  })->then (sub {
    return $http->close;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 6, name => 'WS handshake error - multiple keys';

test {
  my $c = shift;
  my $path = rand;
  my $invoked;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $req->send_response_headers
        ({status => 201, status_text => 'OK'}, content_length => 0);
    $req->close_response;
    $invoked = 1;
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  $http->request (path => [$path], headers => {
    Upgrade => 'websocket',
    Connection => 'upgrade',
    'Sec-WebSocket-Version' => 13,
  })->then (sub {
    my $res = $_[0];
    test {
      ok ! $invoked;
      is $res->status, 400;
      is $res->status_text, 'Bad Request';
      is $res->header ('Connection'), 'close';
      is $res->header ('Content-Type'), 'text/html; charset=utf-8';
      is $res->body_bytes, q{<!DOCTYPE html><html>
<head><title>400 Bad Request</title></head>
<body>400 Bad Request</body></html>
};
    } $c;
  }, sub {
    test {
      ok 0;
    } $c;
  })->then (sub {
    return $http->close;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 6, name => 'WS handshake error - no key';

test {
  my $c = shift;
  my $path = rand;
  my $invoked;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $req->send_response_headers
        ({status => 201, status_text => 'OK'}, content_length => 0);
    $req->close_response;
    $invoked = 1;
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  $http->request (path => [$path], headers => {
    Upgrade => 'websocket',
    Connection => 'upgrade',
    'Sec-WebSocket-Version' => 13,
    'Sec-WebSocket-Key' => 'abcdef1234567890ABCDEF==',
    'Content-Length' => '43abx',
  })->then (sub {
    my $res = $_[0];
    test {
      ok ! $invoked;
      is $res->status, 400;
      is $res->status_text, 'Bad Request';
      is $res->header ('Connection'), 'close';
      is $res->header ('Content-Type'), 'text/html; charset=utf-8';
      is $res->body_bytes, q{<!DOCTYPE html><html>
<head><title>400 Bad Request</title></head>
<body>400 Bad Request</body></html>
};
    } $c;
  }, sub {
    test {
      ok 0;
    } $c;
  })->then (sub {
    return $http->close;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 6, name => 'WS handshake error - Bad Content-Length';

# XXX CONNECT request-target
# XXX  CONNECT closing
# XXX CONNECT content_length
# XXX non-WS 1xx
# XXX WS tests

run_tests;

=head1 LICENSE

Copyright 2016 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
