use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->child ('t_deps/lib');
use lib glob path (__FILE__)->parent->parent->child ('t_deps/modules/*/lib');
use Web::Host;
use Web::URL;
use Web::Transport::TCPTransport;
use Web::Transport::UNIXDomainSocketTransport;
use Web::Transport::ConnectionClient;
use Web::Transport::WSClient;
use Web::Transport::HTTPServerConnection;
use AnyEvent::Socket;
use Test::Certificates;
use Test::X1;
use Test::More;
use AnyEvent;
use Promised::Flow;

$Web::Transport::HTTPServerConnection::ReadTimeout = 10;
my $GlobalCV = AE::cv;

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
my $TLSOrigin;
my $WSOrigin;
my $UnixPath = path (__FILE__)->parent->parent->child
    ('local/test/' . rand)->absolute;
$UnixPath->parent->mkpath;
my $HandleRequestHeaders = {};
{
  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $tls_port = find_listenable_port;
  $Origin = Web::URL->parse_string ("http://$host:$port");
  $WSOrigin = Web::URL->parse_string ("ws://$host:$port");

  my $cb = sub {
    my ($self, $type) = @_;
    if ($type eq 'headers') {
      my $req = $_[2];
      my $handler = $HandleRequestHeaders->{$req->{target_url}->path} ||
                    $HandleRequestHeaders->{$req->{target_url}->hostport};
      if (defined $handler) {
        $self->{body} = '';
        $handler->($self, $req);
      } elsif ($req->{target_url}->path eq '/') {
        $self->send_response_headers
            ({status => 404, status_text => 'Not Found (/)'}, close => 1);
        $self->close_response;
      } else {
        die "No handler for |@{[$req->{target_url}->stringify]}|";
      }
    } elsif ($type eq 'data') {
      $self->{body} .= $_[2];
      $self->{ondata}->($_[2], $_[3]) if $self->{ondata};
    } elsif ($type eq 'text') {
      $self->{text} .= $_[2];
    } elsif ($type eq 'dataend' or $type eq 'textend' or
             $type eq 'ping' or $type eq 'complete') {
      $self->{$type}->($_[2], $_[3]) if $self->{$type};
      if ($type eq 'complete') {
        delete $self->{$_} for qw(ondata dataend textend ping complete);
      }
    }
  }; # $cb

  my $con_cb = sub {
    my ($self, $type) = @_;
    if ($type eq 'startstream') {
      return $cb;
    }
  }; # $con_cb

  our $server = tcp_server $host, $port, sub {
    my $tcp = Web::Transport::TCPTransport->new
        (fh => $_[0],
         host => Web::Host->parse_string ($_[1]), port => $_[2]);
    my $con = Web::Transport::HTTPServerConnection->new
        (transport => $tcp, cb => $con_cb);
    $GlobalCV->begin;
    promised_cleanup { $GlobalCV->end } $con->closed;
  };

  $TLSOrigin = Web::URL->parse_string ("https://tlstestserver.test:$tls_port");
  {
    package TLSTestResolver;
    sub new {
      return bless {}, $_[0];
    }
    sub resolve ($$) {
      return Promise->resolve (Web::Host->parse_string ($host));
    }
  }
  my $cert_args = {host => 'tlstestserver.test'};
  Test::Certificates->wait_create_cert ($cert_args);
  our $tls_server = tcp_server $host, $tls_port, sub {
    my $tcp = Web::Transport::TCPTransport->new
        (fh => $_[0],
         host => Web::Host->parse_string ($_[1]), port => $_[2]);
    my $tls = Web::Transport::TLSTransport->new
        (server => 1, transport => $tcp,
         ca_file => Test::Certificates->ca_path ('cert.pem'),
         cert_file => Test::Certificates->cert_path ('cert-chained.pem', $cert_args),
         key_file => Test::Certificates->cert_path ('key.pem', $cert_args));
    my $con = Web::Transport::HTTPServerConnection->new
        (transport => $tls, cb => $con_cb);
    $GlobalCV->begin;
    promised_cleanup { $GlobalCV->end } $con->closed;
  };

  our $unix_server = tcp_server 'unix/', $UnixPath, sub {
    my $con = Web::Transport::HTTPServerConnection->new
        (transport => Web::Transport::UNIXDomainSocketTransport->new (fh => $_[0]),
         cb => $con_cb);
    $GlobalCV->begin;
    promised_cleanup { $GlobalCV->end } $con->closed;
  };
}

test {
  my $c = shift;
  $HandleRequestHeaders->{'/hoge'} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga'],
        ]}, close => 1);
    $self->close_response;
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
  my $path = rand;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga2'],
        ]}, close => 1);
    $self->send_response_data (\'abcde');
    $self->close_response;
    $self->close_response;
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  $http->request (path => [$path])->then (sub {
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
    $self->send_response_headers
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga3'],
        ]});
    $self->send_response_data (\'');
    $self->send_response_data (\'abcde3');
    $self->close_response;
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
  my $rand = rand;
  $HandleRequestHeaders->{"/$rand"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 304, status_text => 'OK', headers => [
          ['Hoge', 'Fuga4'],
        ]});
    eval {
      $self->send_response_data (\'abcde4');
    };
    $x = $@;
    $self->close_response;
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  $http->request (path => [$rand])->then (sub {
    my $res = $_[0];
    test {
      is $res->status, 304;
      is $res->status_text, 'OK';
      is $res->header ('Hoge'), 'Fuga4';
      is $res->header ('Connection'), undef;
      is $res->body_bytes, '';
      like $x, qr{^Not writable for now.* at .+ line @{[__LINE__-15]}};
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
  my $x;
  my $rand = rand;
  $HandleRequestHeaders->{"/$rand"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 204, status_text => 'OK', headers => [
          ['Hoge', 'Fuga4'],
        ]});
    eval {
      $self->send_response_data (\'abcde4');
    };
    $x = $@;
    $self->close_response;
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  $http->request (path => [$rand])->then (sub {
    my $res = $_[0];
    test {
      is $res->status, 204;
      is $res->status_text, 'OK';
      is $res->header ('Hoge'), 'Fuga4';
      is $res->header ('Connection'), undef;
      is $res->body_bytes, '';
      like $x, qr{^Not writable for now.* at .+ line @{[__LINE__-15]}};
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
} n => 6, name => 'no payload body (204) but data';

test {
  my $c = shift;
  $HandleRequestHeaders->{'/hoge5'} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 304, status_text => 'OK', headers => [
          ['Hoge', 'Fuga5'],
        ]});
    $self->close_response;
  };
  $HandleRequestHeaders->{'/hoge6'} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 200, status_text => 'OK', headers => [
          ['Hoge', 'Fuga6'],
        ]});
    $self->send_response_data (\'abcde6');
    $self->close_response;
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
    $self->send_response_headers
        ({status => 200, status_text => 'OK', headers => [
          ['Hoge', 'Fuga7'],
        ]});
    eval {
      $self->send_response_data (\'abcde7');
    };
    $x = $@;
    $self->close_response;
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
      like $x, qr{^Not writable for now.* at .+ line @{[__LINE__-15]}};
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
    $self->send_response_headers
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga8'],
        ]}, content_length => 12);
    $self->send_response_data (\'abcde8');
    $self->send_response_data (\'');
    $self->send_response_data (\'abcde9');
    eval {
      $self->send_response_data (\'abcde10');
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
      like $x, qr{^Not writable for now.* at .+ line @{[__LINE__-14]}};
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
    $self->send_response_headers
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga11'],
        ]}, content_length => 12);
    $self->send_response_data (\'abcd11');
    eval {
      $self->send_response_data (\'abcde12');
    };
    $x = $@;
    $self->send_response_data (\'abcd13');
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
    $self->send_response_headers
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga14'],
        ]}, content_length => 8);
    $self->send_response_data (\'abcdef14');
  };
  $HandleRequestHeaders->{'/hoge15'} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 202, status_text => 'OK', headers => [
          ['Hoge', 'Fuga15'],
        ]}, content_length => 10);
    $self->send_response_data (\'abcdefgh15');
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
    $self->send_response_headers
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga16'],
        ]}, content_length => 0);
    eval {
      $self->send_response_data (\'abcde16');
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
      like $x, qr{^Not writable for now.* at .+ line @{[__LINE__-15]}};
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
  my $path = rand;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga17'],
        ]}, content_length => 10);
    $self->send_response_data (\'abc17');
    $self->close_response;
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  $http->request (path => [$path])->then (sub {
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
    $self->send_response_headers
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga18'],
        ]}, content_length => 5);
    $self->send_response_data (\'abc18');
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
    $self->send_response_headers
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga19'],
        ]});
    $self->send_response_data (\'abc19');
    $self->close_response;
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
    $self->send_response_headers
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga19'],
        ]});
    $self->send_response_data (\'abc19');
    $self->close_response;
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
    $self->send_response_headers
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga21'],
        ]});
    $self->send_response_data (\'abc21');
    $self->send_response_data (\'abc');
    $self->send_response_data (\'xyz');
    $self->close_response;
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
    $self->send_response_headers
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga22'],
        ]}, content_length => 10);
    $self->send_response_data (\'abc22');
    $self->close_response;
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
    $self->send_response_headers
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga23'],
        ]}, close => 1);
    $self->send_response_data (\'abc23');
    $self->close_response;
    eval {
      $self->send_response_data (\'xyz');
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
      like $x, qr{^Not writable for now.* at .+ line @{[__LINE__-14]}};
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
    $self->send_response_headers
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga24'],
        ]}, content_length => 12);
    $self->send_response_data (\'abcd24');
    eval {
      $self->send_response_data (\"\x{5000}");
    };
    $x = $@;
    $self->send_response_data (\'abcdee');
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
  my $rand = rand;
  $HandleRequestHeaders->{"/$rand"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 304, status_text => 'OK', headers => [
          ['Hoge', 'Fuga25'],
        ]}, content_length => 5);
    eval {
      $self->send_response_data (\'abcde');
    };
    $x = $@;
    $self->close_response;
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  $http->request (path => [$rand])->then (sub {
    my $res = $_[0];
    test {
      is $res->status, 304;
      is $res->status_text, 'OK';
      is $res->header ('Hoge'), 'Fuga25';
      is $res->header ('Connection'), undef;
      is $res->header ('Content-Length'), '5';
      is $res->body_bytes, '';
      like $x, qr{^Not writable for now.* at .+ line @{[__LINE__-16]}};
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
  my $rand = rand;
  $HandleRequestHeaders->{"/$rand"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 204, status_text => 'OK', headers => [
          ['Hoge', 'Fuga25'],
        ]}, content_length => 5);
    eval {
      $self->send_response_data (\'abcde');
    };
    $x = $@;
    $self->close_response;
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  $http->request (path => [$rand])->then (sub {
    my $res = $_[0];
    test {
      is $res->status, 204;
      is $res->status_text, 'OK';
      is $res->header ('Hoge'), 'Fuga25';
      is $res->header ('Connection'), undef;
      is $res->header ('Content-Length'), '5';
      is $res->body_bytes, '';
      like $x, qr{^Not writable for now.* at .+ line @{[__LINE__-16]}};
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
} n => 7, name => '204 with Content-Length';

test {
  my $c = shift;
  my $x;
  $HandleRequestHeaders->{'/hoge26'} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 304, status_text => 'OK', headers => [
          ['Hoge', 'Fuga26'],
        ]}, content_length => 0);
    eval {
      $self->send_response_data (\'abcde');
    };
    $x = $@;
    $self->close_response;
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
      like $x, qr{^Not writable for now.* at .+ line @{[__LINE__-16]}};
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
    $self->send_response_headers
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga27'],
        ]});
    $self->send_response_data (\'abc');
    $self->send_response_data (\'');
    $self->send_response_data (\'xyz');
    $self->close_response;
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
  $HandleRequestHeaders->{'hoge28'} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga28'],
        ]});
    $self->send_response_data (\'abc');
    $self->send_response_data (\'');
    $self->send_response_data (\'xyz');
    $self->close_response;
  };

  rawtcp (qq{CONNECT hoge28 HTTP/1.0\x0D\x0Aconnection:keep-alive\x0D\x0AHost: hoge28\x0D\x0A\x0D\x0A})->then (sub {
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
  $HandleRequestHeaders->{'hoge29'} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga29'],
        ]});
    $self->send_response_data (\'abc');
    $self->send_response_data (\'');
    $self->send_response_data (\'xyz');
    $self->close_response;
  };

  rawtcp (qq{CONNECT hoge29 HTTP/1.1\x0D\x0AHost: hoge29\x0D\x0A\x0D\x0A})->then (sub {
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
  $HandleRequestHeaders->{'hoge30'} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga30'],
        ]});
    $self->send_response_data (\'abc');
    $self->send_response_data (\'');
    $self->send_response_data (\'xyz');
    $self->close_response;
    $serverreq = $self;
  };

  rawtcp (qq{CONNECT hoge30 HTTP/1.1\x0D\x0AHost: hoge30\x0D\x0Acontent-length:3\x0D\x0A\x0D\x0Aabcabc})->then (sub {
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
    $self->send_response_headers
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga31'],
        ]});
    $self->send_response_data (\'abc');
    $self->send_response_data (\'');
    $self->send_response_data (\'xyz');
    $self->close_response;
    $serverreq = $self;
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
    $self->send_response_headers
        ({status => 200, status_text => 'OK', headers => [
          ['Hoge', 'Fuga32'],
        ]});
    $self->send_response_data (\'abc');
    $self->send_response_data (\'');
    $self->send_response_data (\'xyz');
    $self->close_response;
    $serverreq = $self;
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
    $self->send_response_headers
        ({status => 101, status_text => 'OK', headers => [
          ['Hoge', 'Fuga33'],
        ]});
    $self->close_response (status => 5678);
    $serverreq = $self;
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
    $self->send_response_headers
        ({status => 201, status_text => 'OK'}, content_length => 0);
    $self->close_response;
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
    $self->send_response_headers
        ({status => 201, status_text => 'OK'}, content_length => 0);
    $self->close_response;
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
} n => 5, name => 'WS handshake - not handshake response 3';

test {
  my $c = shift;
  my $path = rand;
  my $invoked;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 201, status_text => 'OK'}, content_length => 0);
    $self->close_response;
    $invoked = 1;
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  $http->request (path => [$path], headers => {
    Upgrade => 'websocket',
    Connection => 'upgrade',
    'Sec-WebSocket-Version' => 13,
    'Sec-WebSocket-Key' => 'abcdef1234567890ABCDEF==',
    'Content-Length' => 4,
  }, body => 'abcd')->then (sub {
    my $res = $_[0];
    test {
      ok ! $invoked;
      is $res->status, 400;
      is $res->status_text, 'Bad Request';
      is $res->header ('Connection'), 'close';
      like $res->body_bytes, qr{400};
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
} n => 5, name => 'WS handshake with Content-Length - not handshake response';

test {
  my $c = shift;
  my $path = rand;
  my $invoked;
  my $serverreq;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 201, status_text => 'OK'}, content_length => 0, close => 1);
    $self->close_response;
    $serverreq = $self;
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
} n => 6, name => 'WS handshake with Content-Length - not handshake response 2', timeout => 120;

test {
  my $c = shift;
  my $path = rand;
  my $invoked;
  my $serverreq;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 201, status_text => 'OK'}, content_length => 0, close => 1);
    $self->close_response;
    $serverreq = $self;
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
} n => 6, name => 'WS handshake with Content-Length:0 - not handshake response 1', timeout => 120;

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
  my $path = rand;
  my $invoked;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 201, status_text => 'OK'}, content_length => 0);
    $self->close_response;
    $invoked = 1;
  };

  my $url = Web::URL->parse_string (q<ftp://hoge/>);
  my $http = Web::Transport::ConnectionClient->new_from_url ($url);
  $http->proxy_manager (pp [{protocol => 'http', host => $Origin->host,
                             port => $Origin->port}]);
  $http->request (url => $url, headers => {
    Upgrade => 'websocket',
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
    my $error = $_[0];
    test {
      is $error, undef;
    } $c;
  })->then (sub {
    return $http->close;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 6, name => 'WS handshake error - Bad origin';

test {
  my $c = shift;
  my $path = rand;
  my $invoked;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 201, status_text => 'OK'}, content_length => 0);
    $self->close_response;
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
    $self->send_response_headers
        ({status => 201, status_text => 'OK'}, content_length => 0);
    $self->close_response;
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
    $self->send_response_headers
        ({status => 201, status_text => 'OK'}, content_length => 0);
    $self->close_response;
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
    $self->send_response_headers
        ({status => 201, status_text => 'OK'}, content_length => 0);
    $self->close_response;
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
    $self->send_response_headers
        ({status => 201, status_text => 'OK'}, content_length => 0);
    $self->close_response;
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
    $self->send_response_headers
        ({status => 201, status_text => 'OK'}, content_length => 0);
    $self->close_response;
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
    $self->send_response_headers
        ({status => 201, status_text => 'OK'}, content_length => 0);
    $self->close_response;
    $invoked = 1;
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  $http->request (path => [$path], headers => {
    Upgrade => 'websocket',
    Connection => 'upgrade',
    'Sec-WebSocket-Version' => 13,
    'Sec-WebSocket-Key' => 'abcdef1234567890ABCDEF==',
    'Content-Length' => '4abx',
  }, body => 'abcd')->then (sub {
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

test {
  my $c = shift;
  my $path = rand;
  my $serverreq;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 101, status_text => 'Switched!'});
    $self->send_binary_header (5);
    $self->send_response_data (\"abcde");
    $serverreq = $self;
    $self->{dataend} = sub {
      if ($self->{body} =~ /stuvw/) {
        $self->close_response (status => 5678);
      }
    };
  };

  my $received = '';
  my $sent = 0;
  Web::Transport::WSClient->new (
    url => Web::URL->parse_string (qq</$path>, $WSOrigin),
    cb => sub {
      my ($client, $data, $is_text) = @_;
      if (defined $data) {
        $received .= $data;
      } else {
        $received .= '(end)';
      }
      if ($received =~ /abcde/ and not $sent) {
        $client->send_binary ('stuvw');
        $sent = 1;
      }
    },
  )->then (sub {
    my $res = $_[0];
    test {
      is $serverreq->{body}, 'stuvw';
      is $received, '(end)abcde(end)';
      ok ! $res->is_network_error;
      ok $res->ws_closed_cleanly;
      is $res->ws_code, 5678;
      is $res->ws_reason, '';
    } $c;
    done $c;
    undef $c;
  });
} n => 6, name => 'WS handshaked and data (binary)';

test {
  my $c = shift;
  my $path = rand;
  my $serverreq;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 101, status_text => 'Switched!'});
    $self->send_text_header (5);
    $self->send_response_data (\"abcde");
    $serverreq = $self;
    $self->{textend} = sub {
      if ($self->{text} =~ /stuvw/) {
        $self->close_response (status => 5678, reason => 'abc');
      }
    };
  };

  my $received = '';
  my $sent = 0;
  Web::Transport::WSClient->new (
    url => Web::URL->parse_string (qq</$path>, $WSOrigin),
    cb => sub {
      my ($client, $data, $is_text) = @_;
      if ($is_text) {
        if (defined $data) {
          $received .= $data;
        } else {
          $received .= '(end)';
        }
      }
      if ($received =~ /abcde/ and not $sent) {
        $client->send_text ('stuvw');
        $sent = 1;
      }
    },
  )->then (sub {
    my $res = $_[0];
    test {
      is $serverreq->{text}, 'stuvw';
      is $received, 'abcde(end)';
      ok ! $res->is_network_error;
      ok $res->ws_closed_cleanly;
      is $res->ws_code, 5678;
      is $res->ws_reason, 'abc';
    } $c;
    done $c;
    undef $c;
  });
} n => 6, name => 'WS handshaked and data (text)';

test {
  my $c = shift;
  my $path = rand;
  my $serverreq;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 101, status_text => 'Switched!'});
    $self->send_ping (data => "abbba");
    $serverreq = $self;
    $self->{ping} = sub {
      if ($_[1]) {
        $self->close_response (status => 5678, reason => $_[0]);
      }
    };
  };

  my $received = '';
  Web::Transport::WSClient->new (
    url => Web::URL->parse_string (qq</$path>, $WSOrigin),
    cb => sub {
      my ($client, $data, $is_text) = @_;
      $received .= (defined $data ? $data : '(end)');
    },
  )->then (sub {
    my $res = $_[0];
    test {
      is $serverreq->{body}, '';
      is $serverreq->{text}, undef;
      is $received, '(end)';
      ok ! $res->is_network_error;
      ok $res->ws_closed_cleanly;
      is $res->ws_code, 5678;
      is $res->ws_reason, 'abbba';
    } $c;
    done $c;
    undef $c;
  });
} n => 7, name => 'WS ping';

test {
  my $c = shift;
  my $path = rand;
  my $serverreq;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 101, status_text => 'Switched!'});
    $serverreq = $self;
    $self->{ping} = sub {
      unless ($_[1]) {
        $self->close_response (status => 5678, reason => $_[0]);
      }
    };
  };

  my $received = '';
  Web::Transport::WSClient->new (
    url => Web::URL->parse_string (qq</$path>, $WSOrigin),
    cb => sub {
      my ($client, $data, $is_text) = @_;
      $received .= (defined $data ? $data : '(end)');
      $client->{client}->{http}->send_ping (data => "abbba");
    },
  )->then (sub {
    my $res = $_[0];
    test {
      is $serverreq->{body}, '';
      is $serverreq->{text}, undef;
      is $received, '(end)';
      ok ! $res->is_network_error;
      ok $res->ws_closed_cleanly;
      is $res->ws_code, 5678;
      is $res->ws_reason, 'abbba';
    } $c;
    done $c;
    undef $c;
  });
} n => 7, name => 'WS ping';

test {
  my $c = shift;
  my $path = rand;
  my $error;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 101, status_text => 'Switched!'});
    $self->send_binary_header (5);
    eval {
      $self->send_response_data (\"abcdef");
    };
    $error = $@;
    $self->send_response_data (\"12345");
    $self->close_response (status => 5678);
  };

  my $received = '';
  Web::Transport::WSClient->new (
    url => Web::URL->parse_string (qq</$path>, $WSOrigin),
    cb => sub {
      my ($client, $data, $is_text) = @_;
      $received .= defined $data ? $data : '(end)';
    },
  )->then (sub {
    my $res = $_[0];
    test {
      like $error, qr{^Data too long \(given 6 bytes whereas only 5 bytes allowed\) at @{[__FILE__]} line @{[__LINE__-17]}};
      is $received, '(end)12345(end)';
      ok ! $res->is_network_error;
      ok $res->ws_closed_cleanly;
      is $res->ws_code, 5678;
      is $res->ws_reason, '';
    } $c;
    done $c;
    undef $c;
  });
} n => 6, name => 'WS data bad length';

test {
  my $c = shift;
  my $path = rand;
  my $error;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 101, status_text => 'Switched!'});
    $self->send_text_header (5);
    eval {
      $self->send_response_data (\"abcdef");
    };
    $error = $@;
    $self->send_response_data (\"12345");
    $self->close_response (status => 5678);
  };

  my $received = '';
  Web::Transport::WSClient->new (
    url => Web::URL->parse_string (qq</$path>, $WSOrigin),
    cb => sub {
      my ($client, $data, $is_text) = @_;
      $received .= defined $data ? $data : '(end)';
    },
  )->then (sub {
    my $res = $_[0];
    test {
      like $error, qr{^Data too long \(given 6 bytes whereas only 5 bytes allowed\) at @{[__FILE__]} line @{[__LINE__-17]}};
      is $received, '(end)12345(end)';
      ok ! $res->is_network_error;
      ok $res->ws_closed_cleanly;
      is $res->ws_code, 5678;
      is $res->ws_reason, '';
    } $c;
    done $c;
    undef $c;
  });
} n => 6, name => 'WS data bad length';

test {
  my $c = shift;
  my $path = rand;
  my $error;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 101, status_text => 'Switched!'});
    $self->send_text_header (5);
    $self->send_response_data (\"123");
    eval {
      $self->send_response_data (\"abcdef");
    };
    $error = $@;
    $self->send_response_data (\"45");
    $self->close_response (status => 5678);
  };

  my $received = '';
  Web::Transport::WSClient->new (
    url => Web::URL->parse_string (qq</$path>, $WSOrigin),
    cb => sub {
      my ($client, $data, $is_text) = @_;
      $received .= defined $data ? $data : '(end)';
    },
  )->then (sub {
    my $res = $_[0];
    test {
      like $error, qr{^Data too long \(given 6 bytes whereas only 2 bytes allowed\) at @{[__FILE__]} line @{[__LINE__-17]}};
      is $received, '(end)12345(end)';
      ok ! $res->is_network_error;
      ok $res->ws_closed_cleanly;
      is $res->ws_code, 5678;
      is $res->ws_reason, '';
    } $c;
    done $c;
    undef $c;
  });
} n => 6, name => 'WS data bad length';

test {
  my $c = shift;
  my $path = rand;
  my $error;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 101, status_text => 'Switched!'});
    $self->send_text_header (0);
    eval {
      $self->send_response_data (\"abcdef");
    };
    $error = $@;
    $self->close_response (status => 5678);
  };

  my $received = '';
  Web::Transport::WSClient->new (
    url => Web::URL->parse_string (qq</$path>, $WSOrigin),
    cb => sub {
      my ($client, $data, $is_text) = @_;
      $received .= defined $data ? $data : '(end)';
    },
  )->then (sub {
    my $res = $_[0];
    test {
      like $error, qr{^Not writable for now.* at @{[__FILE__]} line @{[__LINE__-16]}};
      is $received, '(end)(end)';
      ok ! $res->is_network_error;
      ok $res->ws_closed_cleanly;
      is $res->ws_code, 5678;
      is $res->ws_reason, '';
    } $c;
    done $c;
    undef $c;
  });
} n => 6, name => 'WS data bad length';

test {
  my $c = shift;
  my $path = rand;
  my $error;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 101, status_text => 'Switched!'});
    eval {
      $self->send_response_data (\"abcdef");
    };
    $self->send_text_header (1);
    $self->send_response_data (\"1");
    $error = $@;
    $self->close_response (status => 5678);
  };

  my $received = '';
  Web::Transport::WSClient->new (
    url => Web::URL->parse_string (qq</$path>, $WSOrigin),
    cb => sub {
      my ($client, $data, $is_text) = @_;
      $received .= defined $data ? $data : '(end)';
    },
  )->then (sub {
    my $res = $_[0];
    test {
      like $error, qr{^Not writable for now.* at @{[__FILE__]} line @{[__LINE__-18]}};
      is $received, '(end)1(end)';
      ok ! $res->is_network_error;
      ok $res->ws_closed_cleanly;
      is $res->ws_code, 5678;
      is $res->ws_reason, '';
    } $c;
    done $c;
    undef $c;
  });
} n => 6, name => 'WS data bad length';

test {
  my $c = shift;
  my $path = rand;
  my $error;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 101, status_text => 'Switched!'});
    $self->send_binary_header (5);
    $self->send_response_data (\"123");
    eval {
      $self->send_text_header (4);
    };
    $self->send_response_data (\"45");
    $error = $@;
    $self->close_response (status => 5678);
  };

  my $received = '';
  Web::Transport::WSClient->new (
    url => Web::URL->parse_string (qq</$path>, $WSOrigin),
    cb => sub {
      my ($client, $data, $is_text) = @_;
      $received .= defined $data ? $data : '(end)';
    },
  )->then (sub {
    my $res = $_[0];
    test {
      like $error, qr{^Bad state at @{[__FILE__]} line @{[__LINE__-17]}};
      is $received, '(end)12345(end)';
      ok ! $res->is_network_error;
      ok $res->ws_closed_cleanly;
      is $res->ws_code, 5678;
      is $res->ws_reason, '';
    } $c;
    done $c;
    undef $c;
  });
} n => 6, name => 'WS data bad length';

test {
  my $c = shift;
  my $path = rand;
  my $error;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 101, status_text => 'Switched!'});
    $self->send_binary_header (5);
    $self->send_response_data (\"123");
    eval {
      $self->send_binary_header (4);
    };
    $self->send_response_data (\"45");
    $error = $@;
    $self->close_response (status => 5678);
  };

  my $received = '';
  Web::Transport::WSClient->new (
    url => Web::URL->parse_string (qq</$path>, $WSOrigin),
    cb => sub {
      my ($client, $data, $is_text) = @_;
      $received .= defined $data ? $data : '(end)';
    },
  )->then (sub {
    my $res = $_[0];
    test {
      like $error, qr{^Bad state at @{[__FILE__]} line @{[__LINE__-17]}};
      is $received, '(end)12345(end)';
      ok ! $res->is_network_error;
      ok $res->ws_closed_cleanly;
      is $res->ws_code, 5678;
      is $res->ws_reason, '';
    } $c;
    done $c;
    undef $c;
  });
} n => 6, name => 'WS data bad length';

test {
  my $c = shift;
  my $path = rand;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 101, status_text => 'Switched!'});
    $self->send_binary_header (5);
    $self->send_response_data (\"123");
    $self->close_response (status => 4056);
  };

  my $received = '';
  Web::Transport::WSClient->new (
    url => Web::URL->parse_string (qq</$path>, $WSOrigin),
    cb => sub {
      my ($client, $data, $is_text) = @_;
      $received .= defined $data ? $data : '(end)';
    },
  )->then (sub {
    my $res = $_[0];
    test {
      is $received, '(end)';
      ok ! $res->is_network_error;
      ok ! $res->ws_closed_cleanly;
      is $res->ws_code, 1006;
      is $res->ws_reason, '';
    } $c;
    done $c;
    undef $c;
  });
} n => 5, name => 'WS data bad length';

test {
  my $c = shift;
  my $error;
  my $path = rand;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 101, status_text => 'Switched!'});
    $self->close_response (status => 4056);
    eval {
      $self->send_binary_header (5);
    };
    $error = $@;
  };

  my $received = '';
  Web::Transport::WSClient->new (
    url => Web::URL->parse_string (qq</$path>, $WSOrigin),
    cb => sub {
      my ($client, $data, $is_text) = @_;
      $received .= defined $data ? $data : '(end)';
    },
  )->then (sub {
    my $res = $_[0];
    test {
      like $error, qr{^Bad state at @{[__FILE__]} line @{[__LINE__-15]}};
      is $received, '(end)';
      ok ! $res->is_network_error;
      ok $res->ws_closed_cleanly;
      is $res->ws_code, 4056;
      is $res->ws_reason, '';
    } $c;
    done $c;
    undef $c;
  });
} n => 6, name => 'WS data bad state';

test {
  my $c = shift;
  my $path = rand;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 101, status_text => 'Switched!'});
    $self->close_response (status => 4056);
    $self->close_response (status => 5678);
  };

  my $received = '';
  Web::Transport::WSClient->new (
    url => Web::URL->parse_string (qq</$path>, $WSOrigin),
    cb => sub {
      my ($client, $data, $is_text) = @_;
      $received .= defined $data ? $data : '(end)';
    },
  )->then (sub {
    my $res = $_[0];
    test {
      is $received, '(end)';
      ok ! $res->is_network_error;
      ok $res->ws_closed_cleanly;
      is $res->ws_code, 4056;
      is $res->ws_reason, '';
    } $c;
    done $c;
    undef $c;
  });
} n => 5, name => 'WS data bad state';

{
  package TestURLForCONNECT;
  push our @ISA, qw(Web::URL);

  sub hostport ($) {
    my $p = $_[0]->path;
    $p =~ s{^/}{};
    return $p;
  } # hostport

  sub pathquery ($) {
    return $_[0]->hostport;
  } # pathquery
}

test {
  my $c = shift;
  my $path = rand;
  my $serverreq;
  $HandleRequestHeaders->{"$path.test"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 200, status_text => 'Switched!'});
    $self->send_response_data (\"abcde");
    $serverreq = $self;
    $self->{ondata} = sub {
      if ($self->{body} =~ /stuvw/) {
        $self->close_response (status => 5678, reason => 'abc');
      }
    };
  };

  my $url = Web::URL->parse_string ("/$path.test", $Origin);
  bless $url, 'TestURLForCONNECT';
  my $received = '';
  my $client = Web::Transport::ConnectionClient->new_from_url ($url);
  my $http = Web::Transport::ClientBareConnection->new_from_url ($url);
  $http->parent_id ('L' . __LINE__);
  $http->proxy_manager ($client->proxy_manager);
  $http->resolver ($client->resolver);
  $http->request ('CONNECT', $url, [], undef, 0, 0, sub {
    if (defined $_[2]) {
      $received .= $_[2];
      if ($received =~ /abcde/) {
        $http->{http}->send_data (\'stuvw');
      }
    } else {
      $received .= '(end)';
      $http->{http}->send_data (\'abc');
      my $timer; $timer = AE::timer 1, 0, sub {
        undef $timer;
        $http->close;
      };
    }
  })->then (sub {
    my ($res, $result) = @{$_[0]};
    test {
      is $serverreq->{body}, 'stuvwabc';
      is $received, 'abcde(end)';
      ok ! $result->{failed};
      is $result->{message}, undef;
    } $c;
  })->catch (sub {
    my $error = $_[0];
    test {
      is $error, undef, "No error";
    } $c;
  })->then (sub {
    return $http->close;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 4, name => 'CONNECT data';

test {
  my $c = shift;
  my $path = rand;
  my $serverreq;
  $HandleRequestHeaders->{"$path.test"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 200, status_text => 'Switched!'});
    $self->send_response_data (\"abcde");
    $serverreq = $self;
    $self->{ondata} = sub {
      if ($self->{body} =~ /stuvw/) {
        $self->close_response (status => 5678, reason => 'abc');
      }
    };
  };

  my $url = Web::URL->parse_string ("/$path.test", $Origin);
  bless $url, 'TestURLForCONNECT';
  my $received = '';
  my $client = Web::Transport::ConnectionClient->new_from_url ($url);
  my $http = Web::Transport::ClientBareConnection->new_from_url ($url);
  $http->parent_id ('x');
  $http->proxy_manager ($client->proxy_manager);
  $http->resolver ($client->resolver);
  $http->request ('CONNECT', $url, [['Content-Length', '9']], undef, 0, 0, sub {
    if (defined $_[2]) {
      $received .= $_[2];
      if ($received =~ /abcde/) {
        $http->{http}->send_data (\'stuvw');
      }
    } else {
      $received .= '(end)';
      $http->close;
    }
  })->then (sub {
    my ($res, $result) = @{$_[0]};
    test {
      is $serverreq->{body}, 'stuvw';
      is $received, 'abcde(end)';
      ok ! $result->{failed};
      is $result->{message}, undef;
    } $c;
  })->catch (sub {
    my $error = $_[0];
    test {
      is $error, undef, "No error";
    } $c;
  })->then (sub {
    return $http->close;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 4, name => 'CONNECT data with broken Content-Length (request)';

test {
  my $c = shift;
  my $path = rand;
  my $serverreq;
  $HandleRequestHeaders->{"$path.test"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 200, status_text => 'Switched!',
          headers => [['Content-Length', '12']]});
    $self->send_response_data (\"abcde");
    $serverreq = $self;
    $self->{ondata} = sub {
      if ($self->{body} =~ /stuvw/) {
        $self->close_response (status => 5678, reason => 'abc');
      }
    };
  };

  my $url = Web::URL->parse_string ("/$path.test", $Origin);
  bless $url, 'TestURLForCONNECT';
  my $received = '';
  my $client = Web::Transport::ConnectionClient->new_from_url ($url);
  my $http = Web::Transport::ClientBareConnection->new_from_url ($url);
  $http->parent_id ('x');
  $http->proxy_manager ($client->proxy_manager);
  $http->resolver ($client->resolver);
  $http->request ('CONNECT', $url, [], undef, 0, 0, sub {
    if (defined $_[2]) {
      $received .= $_[2];
      if ($received =~ /abcde/) {
        $http->{http}->send_data (\'stuvw');
      }
    } else {
      $received .= '(end)';
      $http->close;
    }
  })->then (sub {
    my ($res, $result) = @{$_[0]};
    test {
      is $serverreq->{body}, 'stuvw';
      is $received, 'abcde(end)';
      ok ! $result->{failed};
      is $result->{message}, undef;
    } $c;
  })->catch (sub {
    my $error = $_[0];
    test {
      is $error, undef, "No error";
    } $c;
  })->then (sub {
    return $http->close;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 4, name => 'CONNECT data with broken Content-Length (response)';

test {
  my $c = shift;
  my $serverreq;
  my $error;
  my $path = rand;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    eval {
      $self->send_response_headers
          ({status => 101, status_text => 'Switched!'});
    };
    $self->send_response_headers
        ({status => 200, status_text => 'O.K.'});
    $error = $@;
    $self->send_response_data (\"abcde");
    $self->close_response;
    $serverreq = $self;
  };

  my $url = Web::URL->parse_string ("/$path", $Origin);
  my $received = '';
  my $client = Web::Transport::ConnectionClient->new_from_url ($url);
  my $http = Web::Transport::ClientBareConnection->new_from_url ($url);
  $http->parent_id ('x');
  $http->proxy_manager ($client->proxy_manager);
  $http->resolver ($client->resolver);
  $http->request ('GET', $url, [], undef, 0, 0, sub {
    if (defined $_[2]) {
      $received .= $_[2];
    } else {
      $received .= '(end)';
      $http->close;
    }
  })->then (sub {
    my ($res, $result) = @{$_[0]};
    test {
      like $error, qr{^1xx response not supported at @{[__FILE__]} line @{[__LINE__-28]}};
      is $serverreq->{body}, '';
      is $received, 'abcde(end)';
      ok ! $result->{failed};
      is $result->{message}, undef;
    } $c;
  })->catch (sub {
    my $error = $_[0];
    test {
      is $error, undef, "No error";
    } $c;
  })->then (sub {
    return $http->close;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 5, name => '1xx response';

test {
  my $c = shift;
  my $path = rand;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 201, status_text => 'o'}, close => 1, content_length => 0);
  };

  rawtcp (qq{GET /$path HTTP/1.1\x0D\x0AHost: @{[$Origin->hostport]}\x0D\x0A\x0D\x0A})->then (sub {
    my $data = $_[0];
    test {
      like $data, qr{\AHTTP/1.1 201 o};
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 1, name => 'request-target GET origin-path';

test {
  my $c = shift;
  my $path = rand;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 201, status_text => 'o'}, close => 1);
    $self->send_response_data (\'ok!');
    $self->close_response;
  };

  rawtcp (qq{GET /$path\x0D\x0A})->then (sub {
    my $data = $_[0];
    test {
      is $data, q{ok!};
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 1, name => 'request-target GET origin-path HTTP/0.9';

test {
  my $c = shift;
  my $path = rand;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 201, status_text => 'o'}, close => 1);
    $self->send_response_data (\($req->{target_url}->stringify));
    $self->close_response;
  };

  rawtcp (qq{GET http://@{[$Origin->hostport]}/$path HTTP/1.1\x0D\x0AHost: @{[$Origin->hostport]}\x0D\x0A\x0D\x0A})->then (sub {
    my $data = $_[0];
    test {
      like $data, qr{\AHTTP/1.1 201 o};
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 1, name => 'request-target GET absolute-path';

test {
  my $c = shift;
  my $path = rand;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 201, status_text => 'o'}, close => 1);
    $self->send_response_data (\'ok!');
    $self->close_response;
  };

  rawtcp (qq{GET http://foo/$path\x0D\x0A})->then (sub {
    my $data = $_[0];
    test {
      is $data, q{ok!};
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 1, name => 'request-target GET absolute-path HTTP/0.9';

test {
  my $c = shift;
  my $path = rand;
  my $invoked = 0;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 201, status_text => 'o'}, close => 1);
    $self->send_response_data (\($req->{target_url}->stringify));
    $self->close_response;
    $invoked++;
  };

  rawtcp (qq{GET @{[$Origin->hostport]} HTTP/1.1\x0D\x0AHost: @{[$Origin->hostport]}\x0D\x0A\x0D\x0A})->then (sub {
    my $data = $_[0];
    test {
      like $data, qr{\AHTTP/1.1 400 Bad Request};
      is $invoked, 0;
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 2, name => 'request-target GET authority-path';

test {
  my $c = shift;
  my $path = rand;
  my $invoked = 0;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 201, status_text => 'o'}, close => 1);
    $self->send_response_data (\($req->{target_url}->stringify));
    $self->close_response;
    $invoked++;
  };

  rawtcp (qq{GET * HTTP/1.1\x0D\x0AHost: @{[$Origin->hostport]}\x0D\x0A\x0D\x0A})->then (sub {
    my $data = $_[0];
    test {
      like $data, qr{\AHTTP/1.1 400 Bad Request};
      is $invoked, 0;
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 2, name => 'request-target GET asterisk-path';

test {
  my $c = shift;
  my $path = rand;
  my $invoked = 0;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 201, status_text => 'o'}, close => 1);
    $self->send_response_data (\($req->{target_url}->stringify));
    $self->close_response;
    $invoked++;
  };

  rawtcp (qq{GET http://hoge$path HTTP/1.1\x0D\x0AHost: @{[$Origin->hostport]}\x0D\x0A\x0D\x0A})->then (sub {
    my $data = $_[0];
    test {
      like $data, qr{\AHTTP/1.1 400 Bad Request};
      is $invoked, 0;
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 2, name => 'request-target GET absolute-path, Host: mismatch';

test {
  my $c = shift;
  my $path = rand;
  my $invoked = 0;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 201, status_text => 'o'}, close => 1);
    $self->send_response_data (\($req->{target_url}->stringify));
    $self->close_response;
    $invoked++;
  };

  rawtcp (qq{GET mailto://@{[$Origin->hostport]}/$path HTTP/1.1\x0D\x0AHost: @{[$Origin->hostport]}\x0D\x0A\x0D\x0A})->then (sub {
    my $data = $_[0];
    test {
      like $data, qr{\AHTTP/1.1 400 Bad Request};
      is $invoked, 0;
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 2, name => 'request-target GET bad absolute-path';

test {
  my $c = shift;
  my $path = rand;
  my $invoked = 0;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 201, status_text => 'o'}, close => 1);
    $self->send_response_data (\($req->{target_url}->stringify));
    $self->close_response;
    $invoked++;
  };

  rawtcp (qq{GET https://@{[$Origin->hostport]}/$path HTTP/1.1\x0D\x0AHost: @{[$Origin->hostport]}\x0D\x0A\x0D\x0A})->then (sub {
    my $data = $_[0];
    test {
      like $data, qr{\AHTTP/1.1 201 o};
      is $invoked, 1;
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 2, name => 'request-target GET https: URL scheme';

test {
  my $c = shift;
  my $path = rand;
  my $invoked = 0;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 201, status_text => 'o'}, close => 1);
    $self->send_response_data (\($req->{target_url}->stringify));
    $self->close_response;
    $invoked++;
  };

  rawtcp (qq{GET https://foobar/$path HTTP/1.1\x0D\x0AHost: foobar\x0D\x0A\x0D\x0A})->then (sub {
    my $data = $_[0];
    test {
      like $data, qr{\AHTTP/1.1 201 o};
      is $invoked, 1;
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 2, name => 'request-target GET https: URL scheme';

test {
  my $c = shift;
  my $path = rand;
  my $invoked = 0;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 201, status_text => 'o'}, close => 1);
    $self->send_response_data (\($req->{target_url}->stringify));
    $self->close_response;
    $invoked++;
  };

  rawtcp (qq{GET https://foobar/$path HTTP/1.1\x0D\x0AHost: foobar:443\x0D\x0A\x0D\x0A})->then (sub {
    my $data = $_[0];
    test {
      like $data, qr{\AHTTP/1.1 201 o};
      is $invoked, 1;
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 2, name => 'request-target GET https: URL scheme';

test {
  my $c = shift;
  my $path = rand;
  my $invoked = 0;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 201, status_text => 'o'}, close => 1);
    $self->send_response_data (\($req->{target_url}->stringify));
    $self->close_response;
    $invoked++;
  };

  rawtcp (qq{GET ftp://foobar/$path HTTP/1.1\x0D\x0AHost: foobar\x0D\x0A\x0D\x0A})->then (sub {
    my $data = $_[0];
    test {
      like $data, qr{\AHTTP/1.1 201 o};
      is $invoked, 1;
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 2, name => 'request-target GET ftp: URL scheme';

test {
  my $c = shift;
  my $path = rand;
  my $invoked = 0;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 201, status_text => 'o'}, close => 1);
    $self->send_response_data (\($req->{target_url}->stringify));
    $self->close_response;
    $invoked++;
  };

  rawtcp (qq{GET ftp://foobar:21/$path HTTP/1.1\x0D\x0AHost: foobar\x0D\x0A\x0D\x0A})->then (sub {
    my $data = $_[0];
    test {
      like $data, qr{\AHTTP/1.1 201 o};
      is $invoked, 1;
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 2, name => 'request-target GET ftp: URL scheme';

test {
  my $c = shift;
  my $path = rand;
  my $invoked = 0;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 201, status_text => 'o'}, close => 1);
    $self->send_response_data (\($req->{target_url}->stringify));
    $self->close_response;
    $invoked++;
  };

  rawtcp (qq{GET ftp://foobar:80/$path HTTP/1.1\x0D\x0AHost: foobar\x0D\x0A\x0D\x0A})->then (sub {
    my $data = $_[0];
    test {
      like $data, qr{\AHTTP/1.1 400 Bad Request};
      is $invoked, 0;
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 2, name => 'request-target GET ftp: URL scheme';

test {
  my $c = shift;
  my $path = rand;
  my $invoked = 0;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 201, status_text => 'o'}, close => 1);
    $self->send_response_data (\($req->{target_url}->stringify));
    $self->close_response;
    $invoked++;
  };

  rawtcp (qq{GET http://foobar:21/$path HTTP/1.1\x0D\x0AHost: foobar:021\x0D\x0A\x0D\x0A})->then (sub {
    my $data = $_[0];
    test {
      like $data, qr{\AHTTP/1.1 201 o};
      is $invoked, 1;
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 2, name => 'request-target GET http: URL scheme';

test {
  my $c = shift;
  my $path = rand;
  my $invoked = 0;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 201, status_text => 'o'}, close => 1);
    $self->send_response_data (\($req->{target_url}->stringify));
    $self->close_response;
    $invoked++;
  };

  rawtcp (qq{GET bad://foobar:21/$path HTTP/1.1\x0D\x0AHost: foobar:21\x0D\x0A\x0D\x0A})->then (sub {
    my $data = $_[0];
    test {
      like $data, qr{\AHTTP/1.1 201 o};
      is $invoked, 1;
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 2, name => 'request-target GET bad: URL scheme';

test {
  my $c = shift;
  my $path = rand;
  my $invoked = 0;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 201, status_text => 'o'}, close => 1);
    $self->send_response_data (\($req->{target_url}->stringify));
    $self->close_response;
    $invoked++;
  };

  rawtcp (qq{GET javascript://foobar/$path HTTP/1.1\x0D\x0AHost: foobar\x0D\x0A\x0D\x0A})->then (sub {
    my $data = $_[0];
    test {
      like $data, qr{\AHTTP/1.1 400 Bad Request};
      is $invoked, 0;
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 2, name => 'request-target GET javascript: URL scheme';

test {
  my $c = shift;
  my $path = rand;
  my $invoked = 0;
  $HandleRequestHeaders->{"//$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 201, status_text => 'o'}, close => 1);
    $self->send_response_data (\($req->{target_url}->stringify));
    $self->close_response;
    $invoked++;
  };

  rawtcp (qq{GET //$path HTTP/1.1\x0D\x0AHost: @{[$Origin->hostport]}\x0D\x0A\x0D\x0A})->then (sub {
    my $data = $_[0];
    test {
      like $data, qr{\AHTTP/1.1 201 o};
      is $invoked, 1;
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 2, name => 'request-target GET //path';

test {
  my $c = shift;
  my $path = rand;
  my $invoked = 0;
  $HandleRequestHeaders->{"/$path%80%FE%AC%FE"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 201, status_text => 'o'}, close => 1);
    $self->send_response_data (\($req->{target_url}->stringify));
    $self->close_response;
    $invoked++;
  };

  rawtcp (qq{GET /$path\x80\xFE\xAC\xFE HTTP/1.1\x0D\x0AHost: @{[$Origin->hostport]}\x0D\x0A\x0D\x0A})->then (sub {
    my $data = $_[0];
    test {
      like $data, qr{\AHTTP/1.1 201 o};
      is $invoked, 1;
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 2, name => 'request-target GET non-ASCII';

test {
  my $c = shift;
  my $path = rand;
  my $invoked = 0;
  $HandleRequestHeaders->{"/$path%80%FE%AC%FE"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 201, status_text => 'o'}, close => 1);
    $self->send_response_data (\($req->{target_url}->stringify));
    $self->close_response;
    $invoked++;
  };

  rawtcp (qq{GET http://@{[$Origin->hostport]}/$path\x80\xFE\xAC\xFE HTTP/1.1\x0D\x0AHost: @{[$Origin->hostport]}\x0D\x0A\x0D\x0A})->then (sub {
    my $data = $_[0];
    test {
      like $data, qr{\AHTTP/1.1 201 o};
      is $invoked, 1;
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 2, name => 'request-target GET non-ASCII';

test {
  my $c = shift;
  my $path = rand;
  my $invoked = 0;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 201, status_text => 'o'}, close => 1);
    $self->send_response_data (\($req->{target_url}->stringify));
    $self->close_response;
    $invoked++;
  };

  rawtcp (qq{GET /$path#abcde HTTP/1.1\x0D\x0AHost: @{[$Origin->hostport]}\x0D\x0A\x0D\x0A})->then (sub {
    my $data = $_[0];
    test {
      like $data, qr{\AHTTP/1.1 201 o};
      is $invoked, 1;
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 2, name => 'request-target GET fragment';

test {
  my $c = shift;
  my $path = rand;
  my $invoked = 0;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 201, status_text => 'o'}, close => 1);
    $self->send_response_data (\($req->{target_url}->stringify));
    $self->close_response;
    $invoked++;
  };

  rawtcp (qq{OPTIONS  /$path HTTP/1.1\x0D\x0AHost: @{[$Origin->hostport]}\x0D\x0A\x0D\x0A})->then (sub {
    my $data = $_[0];
    test {
      like $data, qr{\AHTTP/1.1 201 o};
      is $invoked, 1;
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 2, name => 'request-target OPTIONS';

test {
  my $c = shift;
  my $path = rand;
  my $invoked = 0;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 201, status_text => 'o'}, close => 1);
    $self->send_response_data (\($req->{target_url}->stringify));
    $self->close_response;
    $invoked++;
  };

  rawtcp (qq{OPTIONS http://@{[$Origin->hostport]}/$path HTTP/1.1\x0D\x0AHost: @{[$Origin->hostport]}\x0D\x0A\x0D\x0A})->then (sub {
    my $data = $_[0];
    test {
      like $data, qr{\AHTTP/1.1 201 o};
      is $invoked, 1;
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 2, name => 'request-target OPTIONS';

test {
  my $c = shift;
  my $path = rand;
  my $invoked = 0;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 201, status_text => 'o'}, close => 1);
    $self->send_response_data (\($req->{target_url}->stringify));
    $self->close_response;
    $invoked++;
  };

  rawtcp (qq{OPTIONS $path HTTP/1.1\x0D\x0AHost: @{[$Origin->hostport]}\x0D\x0A\x0D\x0A})->then (sub {
    my $data = $_[0];
    test {
      like $data, qr{\AHTTP/1.1 400 Bad Request};
      is $invoked, 0;
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 2, name => 'request-target OPTIONS';

test {
  my $c = shift;
  rawtcp (qq{OPTIONS * HTTP/1.1\x0D\x0AHost: @{[$Origin->hostport]}\x0D\x0A\x0D\x0A})->then (sub {
    my $data = $_[0];
    test {
      like $data, qr{\AHTTP/1.1 404 Not Found \(/\)};
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 1, name => 'request-target OPTIONS';

test {
  my $c = shift;
  rawtcp (qq{CONNECT * HTTP/1.1\x0D\x0AHost: @{[$Origin->hostport]}\x0D\x0A\x0D\x0A})->then (sub {
    my $data = $_[0];
    test {
      like $data, qr{\AHTTP/1.1 400 Bad Request};
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 1, name => 'request-target CONNECT';

test {
  my $c = shift;
  my $path = rand;
  my $invoked = 0;
  $HandleRequestHeaders->{"$path.test"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 201, status_text => 'o'}, close => 1);
    $self->send_response_data (\($req->{target_url}->stringify));
    $self->close_response;
    $invoked++;
  };

  rawtcp (qq{CONNECT $path.test HTTP/1.1\x0D\x0AHost: $path.test\x0D\x0A\x0D\x0A})->then (sub {
    my $data = $_[0];
    test {
      like $data, qr{\AHTTP/1.1 201 o};
      is $invoked, 1;
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 2, name => 'request-target CONNECT';

test {
  my $c = shift;
  my $path = rand;
  my $invoked = 0;
  $HandleRequestHeaders->{"$path.test"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 201, status_text => 'o'}, close => 1);
    $self->send_response_data (\($req->{target_url}->stringify));
    $self->close_response;
    $invoked++;
  };

  rawtcp (qq{CONNECT $path.test HTTP/1.1\x0D\x0AHost: $path.test2\x0D\x0A\x0D\x0A})->then (sub {
    my $data = $_[0];
    test {
      like $data, qr{\AHTTP/1.1 400 Bad Request};
      is $invoked, 0;
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 2, name => 'request-target CONNECT';

test {
  my $c = shift;
  my $path = rand;
  my $invoked = 0;
  $HandleRequestHeaders->{"/$path.test"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 201, status_text => 'o'}, close => 1);
    $self->send_response_data (\($req->{target_url}->stringify));
    $self->close_response;
    $invoked++;
  };

  rawtcp (qq{CONNECT /$path.test HTTP/1.1\x0D\x0AHost: /$path.test\x0D\x0A\x0D\x0A})->then (sub {
    my $data = $_[0];
    test {
      like $data, qr{\AHTTP/1.1 400 Bad Request};
      is $invoked, 0;
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 2, name => 'request-target CONNECT';

test {
  my $c = shift;
  my $path = rand;
  my $invoked = 0;
  $HandleRequestHeaders->{"/$path.test"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 201, status_text => 'o'}, close => 1);
    $self->send_response_data (\($req->{target_url}->stringify));
    $self->close_response;
    $invoked++;
  };

  rawtcp (qq{CONNECT http://$path.test HTTP/1.1\x0D\x0AHost: $path.test\x0D\x0A\x0D\x0A})->then (sub {
    my $data = $_[0];
    test {
      like $data, qr{\AHTTP/1.1 400 Bad Request};
      is $invoked, 0;
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 2, name => 'request-target CONNECT';

test {
  my $c = shift;
  my $path = rand;
  my $invoked = 0;
  $HandleRequestHeaders->{"$path.test"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 201, status_text => 'o'}, close => 1);
    $self->send_response_data (\($req->{target_url}->stringify));
    $self->close_response;
    $invoked++;
  };

  rawtcp (qq{CONNECT $path.test:80 HTTP/1.1\x0D\x0AHost: $path.test\x0D\x0A\x0D\x0A})->then (sub {
    my $data = $_[0];
    test {
      like $data, qr{\AHTTP/1.1 201 o};
      is $invoked, 1;
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 2, name => 'request-target CONNECT';

test {
  my $c = shift;
  my $path = rand;
  my $invoked = 0;
  $HandleRequestHeaders->{"$path.xn--4gq.test"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 201, status_text => 'o'}, close => 1);
    $self->close_response;
    $invoked++;
  };

  rawtcp (qq{CONNECT $path.\xE4\xB8\x80.test HTTP/1.1\x0D\x0AHost: $path.xn--4gq.test\x0D\x0A\x0D\x0A})->then (sub {
    my $data = $_[0];
    test {
      like $data, qr{\AHTTP/1.1 201 o};
      is $invoked, 1;
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 2, name => 'request-target CONNECT';

test {
  my $c = shift;
  my $path = rand;
  my $invoked = 0;
  $HandleRequestHeaders->{"$path.xn--4gq.test"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 201, status_text => 'o'}, close => 1);
    $self->close_response;
    $invoked++;
  };

  rawtcp (qq{CONNECT $path.xn--4gq.test HTTP/1.1\x0D\x0AHost: $path.\xE4\xB8\x80.test\x0D\x0A\x0D\x0A})->then (sub {
    my $data = $_[0];
    test {
      like $data, qr{\AHTTP/1.1 201 o};
      is $invoked, 1;
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 2, name => 'request-target CONNECT';

test {
  my $c = shift;
  my $path = rand;
  my $invoked = 0;
  $HandleRequestHeaders->{"$path.test"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 201, status_text => 'o'}, close => 1);
    $self->close_response;
    $invoked++;
  };

  rawtcp (qq{CONNECT $path.test HTTP/1.0\x0D\x0A\x0D\x0A})->then (sub {
    my $data = $_[0];
    test {
      like $data, qr{\AHTTP/1.1 201 o};
      is $invoked, 1;
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 2, name => 'request-target CONNECT, no Host: (HTTP/1.0)';

test {
  my $c = shift;
  my $path = rand;
  my $invoked = 0;
  $HandleRequestHeaders->{"$path.test"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 201, status_text => 'o'}, close => 1);
    $self->close_response;
    $invoked++;
  };

  rawtcp (qq{CONNECT $path.test HTTP/1.1\x0D\x0A\x0D\x0A})->then (sub {
    my $data = $_[0];
    test {
      like $data, qr{\AHTTP/1.1 400 Bad Request};
      is $invoked, 0;
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 2, name => 'request-target CONNECT, no Host: (HTTP/1.1)';

test {
  my $c = shift;
  my $path = rand;
  my $invoked = 0;
  $HandleRequestHeaders->{"/$path.test"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 201, status_text => 'o'}, close => 1);
    $self->close_response;
    $invoked++;
  };

  rawtcp (qq{GET /$path.test HTTP/1.0\x0D\x0A\x0D\x0A})->then (sub {
    my $data = $_[0];
    test {
      like $data, qr{\AHTTP/1.1 201 o};
      is $invoked, 1;
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 2, name => 'request-target GET, no Host: (HTTP/1.0)';

test {
  my $c = shift;
  my $path = rand;
  my $invoked = 0;
  $HandleRequestHeaders->{"/$path.test"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 201, status_text => 'o'}, close => 1);
    $self->close_response;
    $invoked++;
  };

  rawtcp (qq{GET /$path.test HTTP/1.1\x0D\x0A\x0D\x0A})->then (sub {
    my $data = $_[0];
    test {
      like $data, qr{\AHTTP/1.1 400 Bad Request};
      is $invoked, 0;
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 2, name => 'request-target GET, no Host: (HTTP/1.1)';

test {
  my $c = shift;
  rawtcp (qq{GET  HTTP/1.1\x0D\x0A\x0D\x0A})->then (sub {
    my $data = $_[0];
    test {
      like $data, qr{\AHTTP/1.1 400 Bad Request};
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 1, name => 'request-target empty (HTTP/1.1)';

test {
  my $c = shift;
  rawtcp (qq{GET  \x0D\x0A\x0D\x0A})->then (sub {
    my $data = $_[0];
    test {
      like $data, qr{<!DOCTYPE html><html>.+400 Bad Request}s;
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 1, name => 'request-target empty (HTTP/0.9)';

test {
  my $c = shift;
  my $path = rand;
  my $serverreq;
  my $exit;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 101, status_text => 'Switched!'});
    $self->send_binary_header (5);
    $self->send_response_data (\"abcde");
    $serverreq = $self;
    $self->{dataend} = sub {
      if ($self->{body} =~ /stuvw/) {
        $self->abort (message => "Test abort\x{6001}");
      }
    };
    $self->{complete} = sub {
      $exit = $_[0];
    };
  };

  my $received = '';
  my $sent = 0;
  Web::Transport::WSClient->new (
    url => Web::URL->parse_string (qq</$path>, $WSOrigin),
    cb => sub {
      my ($client, $data, $is_text) = @_;
      if (defined $data) {
        $received .= $data;
      } else {
        $received .= '(end)';
      }
      if ($received =~ /abcde/ and not $sent) {
        $client->send_binary ('stuvw');
        $sent = 1;
      }
    },
  )->then (sub {
    my $res = $_[0];
    test {
      is $serverreq->{body}, 'stuvw';
      is $received, '(end)abcde(end)';
      ok ! $res->is_network_error;
      ok ! $res->ws_closed_cleanly;
      is $res->ws_code, 1006;
      is $res->ws_reason, '';
      ok $exit->{failed};
      ok $exit->{ws};
      is $exit->{status}, 1006;
      is $exit->{reason}, "Test abort\x{6001}";
      ok ! $exit->{cleanly};
    } $c;
    done $c;
    undef $c;
  });
} n => 11, name => 'server abort - WS';

test {
  my $c = shift;
  my $path = rand;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers ({status => 201, status_text => 'OK'});
    $self->send_response_data (\'abcde');
    promised_sleep (1)->then (sub { $self->abort });
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  $http->request (path => [$path])->then (sub {
    my $res = $_[0];
    test {
      is $res->status, 201;
      is $res->status_text, 'OK';
      is $res->header ('Transfer-Encoding'), 'chunked';
      is $res->body_bytes, 'abcde';
      ok $res->incomplete;
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
} n => 5, name => 'server abort - chunked';

test {
  my $c = shift;
  my $path = rand;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers ({status => 201, status_text => 'OK'},
                                  content_length => 10);
    $self->send_response_data (\'abcde');
    promised_sleep (1)->then (sub { $self->abort });
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  $http->request (path => [$path])->then (sub {
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
} n => 2, name => 'server abort - content-length';

test {
  my $c = shift;
  my $path = rand;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->abort;
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  $http->request (path => [$path])->then (sub {
    my $res = $_[0];
    test {
      ok $res->is_network_error;
      is $res->network_error_message, 'Connection closed without response';
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
} n => 2, name => 'server abort - w/o headers';

test {
  my $c = shift;
  my $tcp = Web::Transport::TCPTransport->new
      (host => $Origin->host, port => $Origin->port);
  my $data = '';
  my $client = Promise->new (sub {
    my $ok = $_[0];
    $tcp->start (sub {
      my ($self, $type) = @_;
      if ($type eq 'readdata') {
        $data .= ${$_[2]};
      } elsif ($type eq 'readeof') {
        #$tcp->push_shutdown;
      } elsif ($type eq 'close') {
        $ok->($data);
      }
    })->then (sub {
      return $tcp->push_shutdown;
    });
  });

  $client->then (sub {
    test {
      like $data, qr{^<!DOCTYPE html><html>.+400 Bad Request.*</html>.*$}s;
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 1, name => 'empty client';

test {
  my $c = shift;
  my $path = rand;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers ({status => 201, status_text => 'OK'});
    $self->send_response_data (\'abcde');
    $self->close_response;
  };

  my $tcp = Web::Transport::TCPTransport->new
      (host => $Origin->host, port => $Origin->port);
  my $data = '';
  my $client = Promise->new (sub {
    my $ok = $_[0];
    $tcp->start (sub {
      my ($self, $type) = @_;
      if ($type eq 'readdata') {
        $data .= ${$_[2]};
      } elsif ($type eq 'readeof') {
        $data .= '(readeof)';
      } elsif ($type eq 'writeeof') {
        $data .= '(writeeof)';
      } elsif ($type eq 'close') {
        $ok->($data);
      }
    })->then (sub {
      $tcp->push_write (\qq{GET /$path HTTP/1.1\x0D\x0AHost: a\x0D\x0A\x0D\x0A});
      return $tcp->push_shutdown;
    });
  });

  $client->then (sub {
    test {
      like $data, qr{abcde}s;
      like $data, qr{\Q(writeeof)\E.*\Q(readeof)\E}s;
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 2, name => 'closed by client';

test {
  my $c = shift;
  my $tcp = Web::Transport::TCPTransport->new
      (host => $Origin->host, port => $Origin->port);
  my $data = '';
  my $client = Promise->new (sub {
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
      #return $tcp->push_shutdown;
    });
  });

  $client->then (sub {
    test {
      is $data, '';
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 1, name => 'empty client, timeout';

test {
  my $c = shift;
  my $path = rand;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers ({status => 201, status_text => 'OK'});
    $self->send_response_data (\'abcde');
    $self->close_response;
  };

  my $tcp = Web::Transport::TCPTransport->new
      (host => $Origin->host, port => $Origin->port);
  my $data = '';
  my $client = Promise->new (sub {
    my $ok = $_[0];
    $tcp->start (sub {
      my ($self, $type) = @_;
      if ($type eq 'readdata') {
        $data .= ${$_[2]};
      } elsif ($type eq 'readeof') {
        #$tcp->push_shutdown;
      } elsif ($type eq 'close') {
        $ok->($data);
      }
    })->then (sub {
      $tcp->push_write (\"GET /$path HTTP/1.1\x0D\x0AHost: test\x0D\x0A");
      return $tcp->_push_reset;
    });
  });

  $client->then (sub {
    test {
      is $data, '';
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 1, name => 'reset before headers';

test {
  my $c = shift;
  my $path = rand;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers ({status => 201, status_text => 'OK'});
    #$self->send_response_data (\'abcde');
    #$self->close_response;
  };

  my $tcp = Web::Transport::TCPTransport->new
      (host => $Origin->host, port => $Origin->port);
  my $data = '';
  my $client = Promise->new (sub {
    my $ok = $_[0];
    $tcp->start (sub {
      my ($self, $type) = @_;
      if ($type eq 'readdata') {
        $data .= ${$_[2]};
      } elsif ($type eq 'readeof') {
        #$tcp->push_shutdown;
      } elsif ($type eq 'close') {
        $ok->($data);
      }
    })->then (sub {
      $tcp->push_write (\"GET /$path HTTP/1.1\x0D\x0AHost: test\x0D\x0A\x0D\x0A");
      return $tcp->_push_reset;
    });
  });

  $client->then (sub {
    test {
      is $data, '';
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 1, name => 'reset after headers';

test {
  my $c = shift;
  my $path = rand;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    #
  };

  my $tcp = Web::Transport::TCPTransport->new
      (host => $Origin->host, port => $Origin->port);
  my $data = '';
  my $client = Promise->new (sub {
    my $ok = $_[0];
    $tcp->start (sub {
      my ($self, $type) = @_;
      if ($type eq 'readdata') {
        $data .= ${$_[2]};
      } elsif ($type eq 'readeof') {
        #$tcp->push_shutdown;
      } elsif ($type eq 'close') {
        $ok->($data);
      }
    })->then (sub {
      $tcp->push_write (\"GET /$path HTTP/1.1\x0D\x0AHost: test\x0D\x0A\x0D\x0A");
      return $tcp->_push_reset;
    });
  });

  $client->then (sub {
    test {
      is $data, '';
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 1, name => 'reset after headers';

test {
  my $c = shift;
  my $path = rand;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers ({status => 201, status_text => 'OK'});
    $self->send_response_data (\'abcde');
    $self->close_response;
  };

  my $tcp = Web::Transport::TCPTransport->new
      (host => $Origin->host, port => $Origin->port);
  my $data = '';
  my $client = Promise->new (sub {
    my $ok = $_[0];
    $tcp->start (sub {
      my ($self, $type) = @_;
      if ($type eq 'readdata') {
        $data .= ${$_[2]};
        $tcp->_push_reset if $data =~ /abcde/;
      } elsif ($type eq 'readeof') {
        #$tcp->push_shutdown;
      } elsif ($type eq 'close') {
        $ok->($data);
      }
    })->then (sub {
      $tcp->push_write (\"GET /$path HTTP/1.1\x0D\x0AHost: test\x0D\x0A\x0D\x0A");
    });
  });

  $client->then (sub {
    test {
      like $data, qr{abcde};
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 1, name => 'reset after sent';

test {
  my $c = shift;
  my $path = rand;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers ({status => 201, status_text => 'OK'});
    $self->send_response_data (\'abcde');
  };

  my $tcp = Web::Transport::TCPTransport->new
      (host => $Origin->host, port => $Origin->port);
  my $data = '';
  my $client = Promise->new (sub {
    my $ok = $_[0];
    $tcp->start (sub {
      my ($self, $type) = @_;
      if ($type eq 'readdata') {
        $data .= ${$_[2]};
        $tcp->_push_reset if $data =~ /abcde/;
      } elsif ($type eq 'readeof') {
        #$tcp->push_shutdown;
      } elsif ($type eq 'close') {
        $ok->($data);
      }
    })->then (sub {
      $tcp->push_write (\"GET /$path HTTP/1.1\x0D\x0AHost: test.domain\x0D\x0A\x0D\x0A");
    });
  });

  $client->then (sub {
    test {
      like $data, qr{abcde};
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 1, name => 'reset after sent';

test {
  my $c = shift;
  my $path = rand;
  my $url;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers ({status => 201, status_text => 'OK'},
                                  close => 1);
    $self->send_response_data (\'abcde');
    $self->close_response;
    $url = $req->{target_url};
  };

  my $tcp = Web::Transport::UNIXDomainSocketTransport->new (path => $UnixPath);
  my $data = '';
  my $client = Promise->new (sub {
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
      $tcp->push_write (\"GET /$path HTTP/1.0\x0D\x0A\x0D\x0A");
    });
  });

  $client->then (sub {
    test {
      is $url->stringify, qq<http://0.0.0.0/$path>;
      like $data, qr{abcde};
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 2, name => 'UNIX socket, no Host:';

test {
  my $c = shift;
  my $path = rand;
  my $url;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers ({status => 201, status_text => 'OK'},
                                  close => 1);
    $self->send_response_data (\'abcde');
    $self->close_response;
    $url = $req->{target_url};
  };

  my $tcp = Web::Transport::TCPTransport->new
      (host => $Origin->host, port => $Origin->port);
  my $data = '';
  my $client = Promise->new (sub {
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
      $tcp->push_write (\"GET /$path HTTP/1.0\x0D\x0AHost:hoge.test\x0D\x0A\x0D\x0A");
    });
  });

  $client->then (sub {
    test {
      is $url->stringify, qq<http://hoge.test/$path>;
      like $data, qr{abcde};
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 2, name => 'HTTP over TCP, URL';

test {
  my $c = shift;
  my $path = rand;
  my $url;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers ({status => 201, status_text => 'OK'},
                                  close => 1);
    $self->send_response_data (\'abcde');
    $self->close_response;
    $url = $req->{target_url};
  };

  my $tcp = Web::Transport::TCPTransport->new
      (host => $Origin->host, port => $Origin->port);
  my $data = '';
  my $client = Promise->new (sub {
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
      $tcp->push_write (\"GET /$path HTTP/1.0\x0D\x0A\x0D\x0A");
    });
  });

  $client->then (sub {
    test {
      my $h = $Origin->hostport;
      is $url->stringify, qq<http://$h/$path>;
      like $data, qr{abcde};
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 2, name => 'HTTP over TCP, URL, no Host:';

test {
  my $c = shift;
  my $path = rand;
  my $url;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers ({status => 201, status_text => 'OK'},
                                  close => 1);
    $self->send_response_data (\'abcde');
    $self->close_response;
    $url = $req->{target_url};
  };

  my $tcp = Web::Transport::UNIXDomainSocketTransport->new (path => $UnixPath);
  my $data = '';
  my $client = Promise->new (sub {
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
      $tcp->push_write (\"GET /$path HTTP/1.1\x0D\x0AHost: test.domain\x0D\x0A\x0D\x0A");
    });
  });

  $client->then (sub {
    test {
      is $url->stringify, qq<http://test.domain/$path>;
      like $data, qr{abcde};
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 2, name => 'UNIX socket';

test {
  my $c = shift;
  my $path = rand;
  my $invoked = 0;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga2'],
        ]}, close => 1);
    $self->send_response_data (\'abcde');
    $self->close_response;
    $invoked++;
  };

  my $origin = $Origin->stringify;
  $origin =~ s/^http/https/;
  $origin = Web::URL->parse_string ($origin);
  my $http = Web::Transport::ConnectionClient->new_from_url ($origin);
  $http->request (path => [$path])->then (sub {
    my $res = $_[0];
    test {
      is $invoked, 0;
      ok $res->is_network_error;
      ok $res->network_error_message;
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
} n => 3, name => 'HTTP server, HTTPS client';

test {
  my $c = shift;
  my $path = rand;
  my $invoked = 0;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga2'],
        ]}, close => 1);
    $self->send_response_data (\'abcde');
    $self->close_response;
    $invoked++;
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($TLSOrigin);
  $http->resolver (TLSTestResolver->new);
  $http->request (path => [$path])->then (sub {
    my $res = $_[0];
    test {
      is $invoked, 0;
      ok $res->is_network_error;
      ok $res->network_error_message;
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
} n => 3, name => 'HTTPS server - no server cert';

test {
  my $c = shift;
  my $path = rand;
  my $invoked = 0;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga2'],
        ]}, close => 1);
    $self->send_response_data (\'abcde');
    $self->close_response;
    $invoked++; 
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($TLSOrigin);
  $http->resolver (TLSTestResolver->new);
  $http->tls_options ({ca_file => Test::Certificates->ca_path ('cert.pem')});
  $http->request (path => [$path])->then (sub {
    my $res = $_[0];
    test {
      is $invoked, 1;
      is $res->status, 201, $res;
      is $res->status_text, 'OK';
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
} n => 3, name => 'HTTPS server - with server cert';

test {
  my $c = shift;
  my $path = rand;
  my $url;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers ({status => 201, status_text => 'OK'},
                                  close => 1);
    $self->send_response_data (\'abcde');
    $self->close_response;
    $url = $req->{target_url};
  };

  my $data = '';
  promised_cleanup { 
    done $c; undef $c;
  } TLSTestResolver->new->resolve ($TLSOrigin->host)->then (sub {
    my $_tcp = Web::Transport::TCPTransport->new
        (host => $_[0],
         port => $TLSOrigin->port || 443);
    my $tcp = Web::Transport::TLSTransport->new
        (transport => $_tcp,
         ca_file => Test::Certificates->ca_path ('cert.pem'));

    return Promise->new (sub {
      my $ok = $_[0];
      my $ng = $_[1];
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
        $tcp->push_write (\"GET /$path HTTP/1.1\x0D\x0AHost: test.domain\x0D\x0A\x0D\x0A");
      });
    });
  })->then (sub {
    test {
      is $url->stringify, qq<https://test.domain/$path>;
      like $data, qr{abcde};
    } $c;
  });
} n => 2, name => 'HTTPS, URL';

test {
  my $c = shift;
  my $path = rand;
  my $url;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers ({status => 201, status_text => 'OK'},
                                  close => 1);
    $self->send_response_data (\'abcde');
    $self->close_response;
    $url = $req->{target_url};
  };

  my $data = '';
  my $host;
  TLSTestResolver->new->resolve ($TLSOrigin->host)->then (sub {
    $host = $_[0];
    my $_tcp = Web::Transport::TCPTransport->new
        (host => $host,
         port => $TLSOrigin->port || 443);
    my $tcp = Web::Transport::TLSTransport->new
        (transport => $_tcp,
         ca_file => Test::Certificates->ca_path ('cert.pem'));

    return Promise->new (sub {
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
        $tcp->push_write (\"GET /$path HTTP/1.0\x0D\x0A\x0D\x0A");
      });
    });
  })->then (sub {
    test {
      my $h = $host->to_ascii . ':' . $TLSOrigin->port;
      is $url->stringify, qq<https://$h/$path>;
      like $data, qr{abcde};
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 2, name => 'HTTPS, URL, no Host:';

test {
  my $c = shift;
  my $path = rand;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->{connection}->server_header ('Hoge/1.4.6');
    $self->send_response_headers
        ({status => 201, status_text => 'OK'}, close => 1);
    $self->close_response;
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  $http->request (path => [$path])->then (sub {
    my $res = $_[0];
    test {
      is $res->header ('Server'), 'Hoge/1.4.6';
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
} n => 1, name => '$con->server_header';

test {
  my $c = shift;
  my $path = rand;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->{connection}->server_header ("\x{3000}a\x00");
    $self->send_response_headers
        ({status => 201, status_text => 'OK'}, close => 1);
    $self->close_response;
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  $http->request (path => [$path])->then (sub {
    my $res = $_[0];
    test {
      is $res->header ('Server'), "\xE3\x80\x80a\x00";
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
} n => 1, name => '$con->server_header';

test {
  my $c = shift;
  my $path = rand;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->{connection}->server_header (undef);
    $self->send_response_headers
        ({status => 201, status_text => 'OK'}, close => 1);
    $self->close_response;
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  $http->request (path => [$path])->then (sub {
    my $res = $_[0];
    test {
      is $res->header ('Server'), "httpd";
      like $res->header ('Date'), qr{^\w+, \d\d \w+ \d{4} \d\d:\d\d:\d\d GMT$};
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
} n => 2, name => '$con->server_header, Date: header';

test {
  my $c = shift;
  my $path = rand;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->{connection}->server_header ("");
    $self->send_response_headers
        ({status => 201, status_text => 'OK'}, close => 1);
    $self->close_response;
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  $http->request (path => [$path])->then (sub {
    my $res = $_[0];
    test {
      is $res->header ('Server'), "";
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
} n => 1, name => '$con->server_header';

test {
  my $c = shift;
  my $path = rand;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->{connection}->server_header ("0");
    $self->send_response_headers
        ({status => 201, status_text => 'OK'}, close => 1);
    $self->close_response;
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  $http->request (path => [$path])->then (sub {
    my $res = $_[0];
    test {
      is $res->header ('Server'), "0";
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
} n => 1, name => '$con->server_header';

test {
  my $c = shift;
  my $path = rand;
  my $error;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->{connection}->server_header ("ab\x0Dvd");
    eval {
      $self->send_response_headers
          ({status => 201, status_text => 'OK'}, close => 1);
    };
    $error = $@;
    $self->abort;
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  $http->request (path => [$path])->then (sub {
    my $res = $_[0];
    test {
      like $error, qr{^Bad header value \|Server: ab\\x0Dvd\| at @{[__FILE__]} line @{[__LINE__-11]}};
      ok $res->is_network_error;
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
} n => 2, name => '$con->server_header newlines';

test {
  my $c = shift;
  my $path = rand;
  my $error;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->{connection}->server_header ("ab\x0Avd");
    eval {
      $self->send_response_headers
          ({status => 201, status_text => 'OK'}, close => 1);
    };
    $error = $@;
    $self->abort;
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  $http->request (path => [$path])->then (sub {
    my $res = $_[0];
    test {
      like $error, qr{^Bad header value \|Server: ab\\x0Avd\| at @{[__FILE__]} line @{[__LINE__-11]}};
      ok $res->is_network_error;
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
} n => 2, name => '$con->server_header newlines';

test {
  my $c = shift;
  my $path = rand;
  my $error;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    eval {
      $self->send_response_headers
          ({status => 201, status_text => 'OK', headers => [
            ["\x00", 'hoge'],
          ]}, close => 1);
    };
    $error = $@;
    $self->abort;
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  $http->request (path => [$path])->then (sub {
    my $res = $_[0];
    test {
      like $error, qr{^Bad header name \|\\x00\| at @{[__FILE__]} line @{[__LINE__-13]}};
      ok $res->is_network_error;
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
} n => 2, name => 'send_response_headers bad header name';

test {
  my $c = shift;
  my $path = rand;
  my $error;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    eval {
      $self->send_response_headers
          ({status => 201, status_text => 'OK', headers => [
            ["", 'hoge'],
          ]}, close => 1);
    };
    $error = $@;
    $self->abort;
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  $http->request (path => [$path])->then (sub {
    my $res = $_[0];
    test {
      like $error, qr{^Bad header name \|\| at @{[__FILE__]} line @{[__LINE__-13]}};
      ok $res->is_network_error;
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
} n => 2, name => 'send_response_headers bad header name';

test {
  my $c = shift;
  my $path = rand;
  my $error;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    eval {
      $self->send_response_headers
          ({status => 201, status_text => 'OK', headers => [
            ["Foo", "x\x0Ab"],
          ]}, close => 1);
    };
    $error = $@;
    $self->abort;
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  $http->request (path => [$path])->then (sub {
    my $res = $_[0];
    test {
      like $error, qr{^Bad header value \|Foo: x\\x0Ab\| at @{[__FILE__]} line @{[__LINE__-13]}};
      ok $res->is_network_error;
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
} n => 2, name => 'send_response_headers bad header value';

test {
  my $c = shift;
  my $path = rand;
  my $error;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    eval {
      $self->send_response_headers
          ({status => 201, status_text => 'OK', headers => [
            [(substr "a\x{5000}", 0, 1), 'hoge'],
          ]}, close => 1);
    };
    $error = $@;
    $self->abort;
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  $http->request (path => [$path])->then (sub {
    my $res = $_[0];
    test {
      like $error, qr{^Header name \|a\| is utf8-flagged at @{[__FILE__]} line @{[__LINE__-13]}};
      ok $res->is_network_error;
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
} n => 2, name => 'send_response_headers bad header name';

test {
  my $c = shift;
  my $path = rand;
  my $error;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    eval {
      $self->send_response_headers
          ({status => 201, status_text => 'OK', headers => [
            ["X", (substr "a\x{5000}", 0, 1)],
          ]}, close => 1);
    };
    $error = $@;
    $self->abort;
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  $http->request (path => [$path])->then (sub {
    my $res = $_[0];
    test {
      like $error, qr{^Header value of \|X\| is utf8-flagged at @{[__FILE__]} line @{[__LINE__-13]}};
      ok $res->is_network_error;
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
} n => 2, name => 'send_response_headers bad header value';

test {
  my $c = shift;
  my $path = rand;
  my $error;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    eval {
      $self->send_response_headers
          ({status => 201, status_text => "a\x0Db"}, close => 1);
    };
    $error = $@;
    $self->abort;
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  $http->request (path => [$path])->then (sub {
    my $res = $_[0];
    test {
      like $error, qr{^Bad status text \|a\\x0Db\| at @{[__FILE__]} line @{[__LINE__-11]}};
      ok $res->is_network_error;
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
} n => 2, name => 'send_response_headers bad status text';

test {
  my $c = shift;
  my $path = rand;
  my $error;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    eval {
      $self->send_response_headers
          ({status => 201, status_text => "a\x{5000}b"}, close => 1);
    };
    $error = $@;
    $self->abort;
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  $http->request (path => [$path])->then (sub {
    my $res = $_[0];
    test {
      like $error, qr{^Status text is utf8-flagged at @{[__FILE__]} line @{[__LINE__-11]}};
      ok $res->is_network_error;
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
} n => 2, name => 'send_response_headers bad status text';

test {
  my $c = shift;
  my $path = rand;
  my $error;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 201, status_text => "OK"}, close => 1);
    eval {
      $self->send_response_headers
          ({status => 202, status_text => "Not OK"}, close => 1);
    };
    $error = $@;
    $self->close_response;
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  $http->request (path => [$path])->then (sub {
    my $res = $_[0];
    test {
      like $error, qr{^\|send_response_headers\| is invoked twice at @{[__FILE__]} line @{[__LINE__-11]}};
      is $res->status, 201;
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
} n => 2, name => 'send_response_headers after headers';

test {
  my $c = shift;
  my $path = rand;
  my $error;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    eval {
      $self->send_response_data (\"abc");
    };
    $error = $@;
    $self->abort;
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  $http->request (path => [$path])->then (sub {
    my $res = $_[0];
    test {
      like $error, qr{^Not writable for now.* at @{[__FILE__]} line @{[__LINE__-10]}};
      ok $res->is_network_error;
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
} n => 2, name => 'send_response_data without headers';

test {
  my $c = shift;
  my $path = rand;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->close_response;
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  $http->request (path => [$path])->then (sub {
    my $res = $_[0];
    test {
      ok $res->is_network_error;
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
} n => 1, name => 'close_response without headers';

test {
  my $c = shift;
  my $path = rand;
  my $error;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 201, status_text => "OK"}, close => 1);
    $self->close_response;
    eval {
      $self->send_response_data (\"abc");
    };
    $error = $@;
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  $http->request (path => [$path])->then (sub {
    my $res = $_[0];
    test {
      like $error, qr{^Not writable for now.* at @{[__FILE__]} line @{[__LINE__-9]}};
      is $res->status, 201;
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
} n => 2, name => 'send_response_data after close';

test {
  my $c = shift;
  my $path = rand;
  my $error;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $self->send_response_headers
        ({status => 201, status_text => "OK"}, close => 1);
    $self->close_response;
    eval {
      $self->send_response_headers
          ({status => 202, status_text => "Not OK"}, close => 1);
    };
    $error = $@;
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  $http->request (path => [$path])->then (sub {
    my $res = $_[0];
    test {
      like $error, qr{^\|send_response_headers\| is invoked twice at @{[__FILE__]} line @{[__LINE__-10]}};
      is $res->status, 201;
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
} n => 2, name => 'send_response_headers after close';

Test::Certificates->wait_create_cert;
$GlobalCV->begin;
run_tests;
$GlobalCV->end;
$GlobalCV->recv;
$HandleRequestHeaders = {};

=head1 LICENSE

Copyright 2016 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
