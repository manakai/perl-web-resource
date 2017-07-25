use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->child ('t_deps/lib');
use lib glob path (__FILE__)->parent->parent->child ('t_deps/modules/*/lib');
use Web::Host;
use Web::URL;
use Web::Transport::TCPStream;
use Web::Transport::UnixStream;
use Web::Transport::TLSStream;
use Web::Transport::HTTPStream;
use AnyEvent::Socket;
use AnyEvent;
use Promised::Flow;
use Test::Certificates;
use Test::X1;
use Test::More;
use Web::Transport::TCPTransport;
use Web::Transport::UNIXDomainSocketTransport;
use Web::Transport::TLSTransport;
use Web::Transport::ConnectionClient;
use Web::Transport::WSClient;
use DataView;
use ArrayBuffer;

$Web::Transport::HTTPStream::ServerConnection::ReadTimeout = 3;
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

  my $server_process = sub {
    my $con = $_[0];
    my $req_reader = $con->received_streams->get_reader;
    my $run; $run = sub {
      return $req_reader->read->then (sub {
        return 0 if $_[0]->{done};
        my $stream = $_[0]->{value};
        $stream->request_ready->then (sub {
          my $req = $stream->{request};
          my $handler = $HandleRequestHeaders->{$req->{target_url}->path} ||
                        $HandleRequestHeaders->{$req->{target_url}->hostport};
          if (defined $handler) {
            $stream->{body} = '';
            my $body_reader = $stream->{request}->{body}->get_reader ('byob');
            my $run; $run = sub {
              return $body_reader->read (DataView->new (ArrayBuffer->new (10)))->then (sub {
                return if $_[0]->{done};
                $stream->{body} .= $_[0]->{value}->manakai_to_string;
                $stream->{ondata}->() if defined $stream->{ondata};
                return $run->();
              });
            }; # $run
            $run->()->then (sub { undef $run }, sub { undef $run });
            $handler->($stream, $req);
          } elsif ($req->{target_url}->path eq '/') {
            return $stream->send_response
                ({status => 404, status_text => 'Not Found (/)'}, close => 1)->then (sub {
              return $stream->{response}->{body}->get_writer->close;
            });
          } else {
            die "No handler for |@{[$req->{target_url}->stringify]}|";
          }
        });
        $stream->closed->then (sub { # XXX
          $stream->{complete}->($_[2], $_[3]) if $stream->{complete};
          delete $stream->{$_} for qw(ondata dataend textend ping complete);
        });
        return $run->();
      });
    }; # $run
    $run->()->then (sub { undef $run }, sub { undef $run });
    #} elsif ($type eq 'text') {
    #  $self->{text} .= $_[2];
    #} elsif ($type eq 'dataend' or $type eq 'textend' or
    #         $type eq 'ping') {
    #  $self->{$type}->($_[2], $_[3]) if $self->{$type};
  }; # $server_process

  our $server = tcp_server $host, $port, sub {
    my $con = Web::Transport::HTTPStream->new_XXXserver
        ({parent => {
           class => 'Web::Transport::TCPStream',
           server => 1,
           fh => $_[0],
           host => Web::Host->parse_string ($_[1]), port => $_[2]
         }});
    $server_process->($con);
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
    my $con = Web::Transport::HTTPStream->new_XXXserver
        ({parent => {
           class => 'Web::Transport::TLSStream',
           server => 1,
           parent => {
             class => 'Web::Transport::TCPStream',
             server => 1,
             fh => $_[0],
             host => Web::Host->parse_string ($_[1]), port => $_[2],
           },
           ca_file => Test::Certificates->ca_path ('cert.pem'),
           cert_file => Test::Certificates->cert_path ('cert-chained.pem', $cert_args),
           key_file => Test::Certificates->cert_path ('key.pem', $cert_args),
         }});
    $server_process->($con);
    $GlobalCV->begin;
    promised_cleanup { $GlobalCV->end } $con->closed;
  };

  our $unix_server = tcp_server 'unix/', $UnixPath, sub {
    my $con = Web::Transport::HTTPStream->new_XXXserver
        ({parent => {
            class => 'Web::Transport::UnixStream',
            server => 1,
            fh => $_[0],
         }});
    $server_process->($con);
    $GlobalCV->begin;
    promised_cleanup { $GlobalCV->end } $con->closed;
  };
}

sub d ($) {
  return DataView->new (ArrayBuffer->new_from_scalarref (\($_[0])));
} # d

test {
  my $c = shift;
  $HandleRequestHeaders->{'/hoge'} = sub {
    my ($self, $req) = @_;
    return $self->send_response
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga'],
        ]}, close => 1)->then (sub {
      return $self->{response}->{body}->get_writer->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga2'],
        ]}, close => 1)->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d 'abcde');
      return $w->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga3'],
        ]})->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d '');
      $w->write (d 'abcde3');
      return $w->close;
    });
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
  my $y;
  my $rand = rand;
  $HandleRequestHeaders->{"/$rand"} = sub {
    my ($self, $req) = @_;
    return $self->send_response
        ({status => 304, status_text => 'OK', headers => [
          ['Hoge', 'Fuga4'],
        ]})->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      return $w->write (d 'abcde4')->catch (sub {
        $x = $_[0];
      })->then (sub {
        return $w->close;
      })->catch (sub {
        $y = $_[0];
      });
    });
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
      like $x, qr{^TypeError: WritableStream is closed at \Q@{[__FILE__]}\E line @{[__LINE__-13]}};
      like $y, qr{^TypeError: WritableStream is closed at \Q@{[__FILE__]}\E line @{[__LINE__-17]}};
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
} n => 7, name => 'no payload body (304) but data';

test {
  my $c = shift;
  my $x;
  my $y;
  my $rand = rand;
  $HandleRequestHeaders->{"/$rand"} = sub {
    my ($self, $req) = @_;
    return $self->send_response
        ({status => 204, status_text => 'OK', headers => [
          ['Hoge', 'Fuga4'],
        ]})->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      return $w->write (d 'abcde4')->catch (sub {
        $x = $_[0];
        return $w->close;
      })->catch (sub {
        $y = $_[0];
      });
    });
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
      like $x, qr{^TypeError: WritableStream is closed at \Q@{[__FILE__]}\E line @{[__LINE__-13]}};
      like $y, qr{^TypeError: WritableStream is closed at \Q@{[__FILE__]}\E line @{[__LINE__-17]}};
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
} n => 7, name => 'no payload body (204) but data';

test {
  my $c = shift;
  $HandleRequestHeaders->{'/hoge5'} = sub {
    my ($self, $req) = @_;
    return $self->send_response
        ({status => 304, status_text => 'OK', headers => [
          ['Hoge', 'Fuga5'],
        ]})->then (sub {
      return $self->{response}->{body}->get_writer->close;
    });
  };
  $HandleRequestHeaders->{'/hoge6'} = sub {
    my ($self, $req) = @_;
    return $self->send_response
        ({status => 200, status_text => 'OK', headers => [
          ['Hoge', 'Fuga6'],
        ]})->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d 'abcde6');
      return $w->close;
    });
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
  my $y;
  $HandleRequestHeaders->{'/hoge7'} = sub {
    my ($self, $req) = @_;
    return $self->send_response
        ({status => 200, status_text => 'OK', headers => [
          ['Hoge', 'Fuga7'],
        ]})->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d 'abcde7')->catch (sub {
        $x = $_[0];
        return $w->close;
      })->catch (sub {
        $y = $_[0];
      });
    });
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
      like $x, qr{^TypeError: WritableStream is closed at \Q@{[__FILE__]}\E line @{[__LINE__-13]}};
      like $y, qr{^TypeError: WritableStream is closed at \Q@{[__FILE__]}\E line @{[__LINE__-17]}};
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
} n => 7, name => 'no payload body (HEAD) but data';

test {
  my $c = shift;
  my $x;
  $HandleRequestHeaders->{'/hoge8'} = sub {
    my ($self, $req) = @_;
    return $self->send_response
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga8'],
        ]}, content_length => 12)->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d 'abcde8');
      $w->write (d '');
      $w->write (d 'abcde9');
      $w->write (d 'abcde10')->catch (sub {
        $x = $_[0];
      });
    });
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
      like $x, qr{^TypeError: Response body is not writable at}; # XXX location
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
} n => 6, name => 'with Content-Length 1';

test {
  my $c = shift;
  my $x;
  my $y;
  my $p;
  $HandleRequestHeaders->{'/hoge11'} = sub {
    my ($self, $req) = @_;
    return $self->send_response
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga11'],
        ]}, content_length => 12)->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d 'abcd11');
      $p = $w->write (d 'abcde12')->catch (sub {
        $x = $_[0];
        return $w->write (d 'abcd13');
      })->catch (sub {
        $y = $_[0];
      });
    });
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  $http->request (path => ['hoge11'])->then (sub {
    my $res = $_[0];
    test {
      ok $res->is_network_error;
    } $c;
    return $p;
  })->then (sub {
    test {
      like $x, qr{^TypeError: Byte length 7 is greater than expected length 6 at}; # XXX location
      like $y, qr{^TypeError: Byte length 7 is greater than expected length 6 at}; # XXX location
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
} n => 3, name => 'with Content-Length 2';

test {
  my $c = shift;
  my @w;
  $HandleRequestHeaders->{'/hoge14'} = sub {
    my ($self, $req) = @_;
    return $self->send_response
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga14'],
        ]}, content_length => 8)->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d 'abcdef14');
      push @w, $w;
    });
  };
  $HandleRequestHeaders->{'/hoge15'} = sub {
    my ($self, $req) = @_;
    return $self->send_response
        ({status => 202, status_text => 'OK', headers => [
          ['Hoge', 'Fuga15'],
        ]}, content_length => 10)->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d 'abcdefgh15');
      push @w, $w;
    });
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
    return promised_map { $_[0]->close } \@w;
  })->then (sub {
    return $http->close;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 12, name => 'with Content-Length 3';

test {
  my $c = shift;
  my $p;
  my $x;
  $HandleRequestHeaders->{'/hoge16'} = sub {
    my ($self, $req) = @_;
    $p = $self->send_response
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga16'],
        ]}, content_length => 0)->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      return $w->write (d 'abcde16')->catch (sub {
        $x = $_[0];
      });
    });
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
    } $c;
    return $p;
  })->then (sub {
    test {
      like $x, qr{^TypeError: WritableStream is closed at \Q@{[__FILE__]}\E line \Q@{[__LINE__-18]}\E};
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
    return $self->send_response
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga17'],
        ]}, content_length => 10)->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d 'abc17');
      return $w->close;
    });
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
  my @w;
  $HandleRequestHeaders->{'/hoge18'} = sub {
    my ($self, $req) = @_;
    return $self->send_response
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga18'],
        ]}, content_length => 5)->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d 'abc18');
      push @w, $w;
    });
  };

  rawtcp (qq{GET /hoge18\x0D\x0A})->then (sub {
    my $data = $_[0];
    test {
      is $data, q{abc18};
    } $c;
  })->then (sub {
    return $w[0]->close;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 1, name => 'HTTP/0.9 response with data';

test {
  my $c = shift;
  $HandleRequestHeaders->{'/hoge19'} = sub {
    my ($self, $req) = @_;
    return $self->send_response
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga19'],
        ]})->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d 'abc19');
      return $w->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga19'],
        ]})->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d 'abc19');
      return $w->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga21'],
        ]})->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d 'abc21');
      $w->write (d 'abc');
      $w->write (d 'xyz');
      return $w->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga22'],
        ]}, content_length => 10)->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d 'abc22');
      return $w->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga23'],
        ]}, close => 1)->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d 'abc23');
      $w->close;
      $w->write (d 'xyz')->catch (sub {
        $x = $_[0];
      });
    });
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
      like $x, qr{^TypeError: WritableStream is closed at \Q@{[__FILE__]}\E line @{[__LINE__-13]}};
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
  my $y;
  my $rand = rand;
  $HandleRequestHeaders->{"/$rand"} = sub {
    my ($self, $req) = @_;
    return $self->send_response
        ({status => 304, status_text => 'OK', headers => [
          ['Hoge', 'Fuga25'],
        ]}, content_length => 5)->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      return $w->write (d 'abcde')->catch (sub {
        $x = $_[0];
        return $w->close;
      })->catch (sub {
        $y = $_[0];
      });
    });
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
      like $x, qr{^TypeError: WritableStream is closed at \Q@{[__FILE__]}\E line @{[__LINE__-14]}};
      like $y, qr{^TypeError: WritableStream is closed at \Q@{[__FILE__]}\E line @{[__LINE__-18]}};
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
} n => 8, name => '304 with Content-Length';

test {
  my $c = shift;
  my $x;
  my $y;
  my $p;
  my $rand = rand;
  $HandleRequestHeaders->{"/$rand"} = sub {
    my ($self, $req) = @_;
    $p = $self->send_response
        ({status => 204, status_text => 'OK', headers => [
          ['Hoge', 'Fuga25'],
        ]}, content_length => 5)->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      return $w->write (d 'abcde')->catch (sub {
        $x = $_[0];
        return $w->close;
      })->catch (sub {
        $y = $_[0];
      });
    });
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
    } $c;
    return $p;
  })->then (sub {
    test {
      like $x, qr{^TypeError: WritableStream is closed at \Q@{[__FILE__]}\E line @{[__LINE__-18]}};
      like $y, qr{^TypeError: WritableStream is closed at \Q@{[__FILE__]}\E line @{[__LINE__-22]}};
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
} n => 8, name => '204 with Content-Length';

test {
  my $c = shift;
  my $x;
  $HandleRequestHeaders->{'/hoge26'} = sub {
    my ($self, $req) = @_;
    return $self->send_response
        ({status => 304, status_text => 'OK', headers => [
          ['Hoge', 'Fuga26'],
        ]}, content_length => 0)->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      return $w->write (d 'abcde')->catch (sub {
        $x = $_[0];
      });
    });
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
      like $x, qr{^TypeError: WritableStream is closed at \Q@{[__FILE__]}\E line @{[__LINE__-14]}};
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
    return $self->send_response
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga27'],
        ]})->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d 'abc');
      $w->write (d '');
      $w->write (d 'xyz');
      return $w->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga28'],
        ]})->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d 'abc');
      $w->write (d '');
      $w->write (d 'xyz');
      return $w->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga29'],
        ]})->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d 'abc');
      $w->write (d '');
      $w->write (d 'xyz');
      return $w->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga30'],
        ]})->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d 'abc');
      $w->write (d '');
      $w->write (d 'xyz');
      $serverreq = $self;
      return $w->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga31'],
        ]})->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d 'abc');
      $w->write (d '');
      $w->write (d 'xyz');
      $serverreq = $self;
      return $w->close;
    });
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
    return $self->send_response
        ({status => 200, status_text => 'OK', headers => [
          ['Hoge', 'Fuga32'],
        ]})->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d 'abc');
      $w->write (d '');
      $w->write (d 'xyz');
      $serverreq = $self;
      return $w->close;
    });
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
    return $self->send_response
        ({status => 101, status_text => 'OK', headers => [
          ['Hoge', 'Fuga33'],
        ]})->then (sub {
      $serverreq = $self;
      # XXX (status => 5678);
      return $self->{response}->{body}->get_writer->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'OK'}, content_length => 0)->then (sub {
      $invoked = 1;
      return $self->{response}->{body}->get_writer->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'OK'}, content_length => 0)->then (sub {
      $invoked = 1;
      return $self->{response}->{body}->get_writer->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'OK'}, content_length => 0)->then (sub {
      $invoked = 1;
      return $self->{response}->{body}->get_writer->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'OK'}, content_length => 0, close => 1)->then (sub {
      $serverreq = $self;
      $invoked = 1;
      return $self->{response}->{body}->get_writer->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'OK'}, content_length => 0, close => 1)->then (sub {
      $serverreq = $self;
      $invoked = 1;
      return $self->{response}->{body}->get_writer->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'OK'}, content_length => 0)->then (sub {
      $invoked = 1;
      return $self->{response}->{body}->get_writer->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'OK'}, content_length => 0)->then (sub {
      $invoked = 1;
      return $self->{response}->{body}->get_writer->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'OK'}, content_length => 0)->then (sub {
      $invoked = 1;
      return $self->{response}->{body}->get_writer->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'OK'}, content_length => 0)->then (sub {
      $invoked = 1;
      return $self->{response}->{body}->get_writer->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'OK'}, content_length => 0)->then (sub {
      $invoked = 1;
      return $self->{response}->{body}->get_writer->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'OK'}, content_length => 0)->then (sub {
      $invoked = 1;
      return $self->{response}->{body}->get_writer->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'OK'}, content_length => 0)->then (sub {
      $invoked = 1;
      return $self->{response}->{body}->get_writer->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'OK'}, content_length => 0)->then (sub {
      $invoked = 1;
      return $self->{response}->{body}->get_writer->close;
    });
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
    return $self->send_response
        ({status => 101, status_text => 'Switched!'})->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $self->send_binary_header (5);
      $w->write (d "abcde");
      $serverreq = $self;
      #XXX
      $self->{dataend} = sub {
        if ($self->{body} =~ /stuvw/) {
          #XXX$self->close_response (status => 5678);
          return $w->close;
        }
      };
    });
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
    return $self->send_response
        ({status => 101, status_text => 'Switched!'})->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $self->send_text_header (5);
      $w->write (d "abcde");
      $serverreq = $self;
      $self->{textend} = sub { # XXX
        if ($self->{text} =~ /stuvw/) {
          #XXXX $self->close_response (status => 5678, reason => 'abc');
          return $w->close;
        }
      };
    });
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
    return $self->send_response
        ({status => 101, status_text => 'Switched!'})->then (sub {
      $self->send_ping (data => "abbba");
      $serverreq = $self;
      $self->{ping} = sub {
        if ($_[1]) {
          #XXX $self->close_response (status => 5678, reason => $_[0]);
          return $self->{response}->{body}->get_writer->close;
        }
      };
    });
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
    return $self->send_response
        ({status => 101, status_text => 'Switched!'})->then (sub {
      $serverreq = $self;
      $self->{ping} = sub {
        unless ($_[1]) {
          #XXX $self->close_response (status => 5678, reason => $_[0]);
          return $self->{response}->{body}->get_writer->close;
        }
      };
    });
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
    return $self->send_response
        ({status => 101, status_text => 'Switched!'})->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $self->send_binary_header (5);
      eval {
        $w->write (d "abcdef");
      };
      $error = $@;
      $w->write (d "12345");
      #XXX $self->close_response (status => 5678);
      return $w->close;
    });
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
    return $self->send_response
        ({status => 101, status_text => 'Switched!'})->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $self->send_text_header (5);
      eval {
        $w->write (d "abcdef");
      };
      $error = $@;
      $w->write (d "12345");
      #XXX $self->close_response (status => 5678);
      return $w->close;
    });
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
    return $self->send_response
        ({status => 101, status_text => 'Switched!'})->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $self->send_text_header (5);
      $w->write (d "123");
      eval {
        $w->write (d "abcdef");
      };
      $error = $@;
      $w->write (d "45");
      #XXX $self->close_response (status => 5678);
      return $w->close;
    });
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
    return $self->send_response
        ({status => 101, status_text => 'Switched!'})->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $self->send_text_header (0);
      eval {
        $w->write (d "abcdef");
      };
      $error = $@;
      #XXX $self->close_response (status => 5678);
      return $w->close;
    });
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
    return $self->send_response
        ({status => 101, status_text => 'Switched!'})->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      eval {
        $w->write (d "abcdef");
      };
      $self->send_text_header (1);
      $w->write (d "1");
      $error = $@;
      #XXX $self->close_response (status => 5678);
      return $w->close;
    });
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
    return $self->send_response
        ({status => 101, status_text => 'Switched!'})->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $self->send_binary_header (5);
      $w->write (d "123");
      eval {
        $self->send_text_header (4);
      };
      $w->write (d "45");
      $error = $@;
      #XXX $self->close_response (status => 5678);
      return $w->close;
    });
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
    return $self->send_response
        ({status => 101, status_text => 'Switched!'})->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $self->send_binary_header (5);
      $w->write (d "123");
      eval {
        $self->send_binary_header (4);
      };
      $w->write (d "45");
      $error = $@;
      #XXX $self->close_response (status => 5678);
      return $w->close;
    });
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
    return $self->send_response
        ({status => 101, status_text => 'Switched!'})->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $self->send_binary_header (5);
      $w->write (d "123");
      #XXX $self->close_response (status => 4056);
      return $w->close;
    });
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
    return $self->send_response
        ({status => 101, status_text => 'Switched!'})->then (sub {
      #XXX $self->close_response (status => 4056);
      return $self->{response}->{body}->get_writer->close;
    })->then (sub {
      eval {
        $self->send_binary_header (5);
      };
      $error = $@;
    });
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
    return $self->send_response
        ({status => 101, status_text => 'Switched!'})->then (sub {
      #XXX $self->close_response (status => 4056);
      return $self->{response}->{body}->get_writer->close;
    });
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
    return $self->send_response
        ({status => 200, status_text => 'Switched!'})->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d "abcde");
      $serverreq = $self;
      $self->{ondata} = sub {
        if ($self->{body} =~ /stuvw/) {
          #XXX $self->close_response (status => 5678, reason => 'abc');
          return $w->close;
        }
      };
    });
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
    return $self->send_response
        ({status => 200, status_text => 'Switched!'})->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d "abcde");
      $serverreq = $self;
      $self->{ondata} = sub {
        if ($self->{body} =~ /stuvw/) {
          # XXX $self->close_response (status => 5678, reason => 'abc');
          return $w->close;
        }
      };
    });
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
    return $self->send_response
        ({status => 200, status_text => 'Switched!',
          headers => [['Content-Length', '12']]})->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d "abcde");
      $serverreq = $self;
      $self->{ondata} = sub {
        if ($self->{body} =~ /stuvw/) {
          # XXX $self->close_response (status => 5678, reason => 'abc');
          return $w->close;
        }
      };
    });
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
    return $self->send_response
        ({status => 101, status_text => 'Switched!'})->catch (sub {
      $error = $_[0];
      return $self->send_response
          ({status => 200, status_text => 'O.K.'});
    })->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d "abcde");
      $serverreq = $self;
      return $w->close;
    });
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
      like $error, qr{^TypeError: 1xx response not supported at @{[__FILE__]} line @{[__LINE__-20]}};
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
    $self->send_response
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
    return $self->send_response
        ({status => 201, status_text => 'o'}, close => 1)->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d 'ok!');
      return $w->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'o'}, close => 1)->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d ($req->{target_url}->stringify));
      return $w->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'o'}, close => 1)->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d 'ok!');
      return $w->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'o'}, close => 1)->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d ($req->{target_url}->stringify));
      $invoked++;
      return $w->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'o'}, close => 1)->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d ($req->{target_url}->stringify));
      $invoked++;
      return $w->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'o'}, close => 1)->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d ($req->{target_url}->stringify));
      $invoked++;
      return $w->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'o'}, close => 1)->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d ($req->{target_url}->stringify));
      $invoked++;
      return $w->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'o'}, close => 1)->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d ($req->{target_url}->stringify));
      $invoked++;
      return $w->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'o'}, close => 1)->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d ($req->{target_url}->stringify));
      $invoked++;
      return $w->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'o'}, close => 1)->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d ($req->{target_url}->stringify));
      $invoked++;
      return $w->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'o'}, close => 1)->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d ($req->{target_url}->stringify));
      $invoked++;
      return $w->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'o'}, close => 1)->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d ($req->{target_url}->stringify));
      $invoked++;
      return $w->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'o'}, close => 1)->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d ($req->{target_url}->stringify));
      $invoked++;
      return $w->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'o'}, close => 1)->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d ($req->{target_url}->stringify));
      $invoked++;
      return $w->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'o'}, close => 1)->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d ($req->{target_url}->stringify));
      $invoked++;
      return $w->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'o'}, close => 1)->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d ($req->{target_url}->stringify));
      $invoked++;
      return $w->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'o'}, close => 1)->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d ($req->{target_url}->stringify));
      $invoked++;
      return $w->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'o'}, close => 1)->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d ($req->{target_url}->stringify));
      $invoked++;
      return $w->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'o'}, close => 1)->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d ($req->{target_url}->stringify));
      $invoked++;
      return $w->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'o'}, close => 1)->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d ($req->{target_url}->stringify));
      $invoked++;
      return $w->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'o'}, close => 1)->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d ($req->{target_url}->stringify));
      $invoked++;
      return $w->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'o'}, close => 1)->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d ($req->{target_url}->stringify));
      $invoked++;
      return $w->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'o'}, close => 1)->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d ($req->{target_url}->stringify));
      $invoked++;
      return $w->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'o'}, close => 1)->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d ($req->{target_url}->stringify));
      $invoked++;
      return $w->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'o'}, close => 1)->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d ($req->{target_url}->stringify));
      $invoked++;
      return $w->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'o'}, close => 1)->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d ($req->{target_url}->stringify));
      $invoked++;
      return $w->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'o'}, close => 1)->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d ($req->{target_url}->stringify));
      $invoked++;
      return $w->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'o'}, close => 1)->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d ($req->{target_url}->stringify));
      $invoked++;
      return $w->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'o'}, close => 1)->then (sub {
      $invoked++;
      return $self->{response}->{body}->get_writer->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'o'}, close => 1)->then (sub {
      $invoked++;
      return $self->{response}->{body}->get_writer->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'o'}, close => 1)->then (sub {
      $invoked++;
      return $self->{response}->{body}->get_writer->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'o'}, close => 1)->then (sub {
      $invoked++;
      return $self->{response}->{body}->get_writer->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'o'}, close => 1)->then (sub {
      $invoked++;
      return $self->{response}->{body}->get_writer->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'o'}, close => 1)->then (sub {
      $invoked++;
      return $self->{response}->{body}->get_writer->close;
    });
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
    return $self->send_response
        ({status => 101, status_text => 'Switched!'})->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $self->send_binary_header (5);
      $w->write (d "abcde");
      $serverreq = $self;
      $self->{dataend} = sub { # XXX
        if ($self->{body} =~ /stuvw/) {
          $self->abort (message => "Test abort\x{6001}");
        }
      };
      $self->{complete} = sub { # XXX
        $exit = $_[0];
      };
    });
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
  my $p;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    $p = $self->send_response ({status => 201, status_text => 'OK'})->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      return $w->write (d 'abcde')->then (sub {
        return promised_sleep (1);
      })->then (sub {
        return $self->abort;
      });
    });
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
    return $self->send_response ({status => 201, status_text => 'OK'},
                                  content_length => 10)->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d 'abcde');
      promised_sleep (1)->then (sub { $self->abort });
    });
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
    return $self->send_response ({status => 201, status_text => 'OK'})->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d 'abcde');
      return $w->close;
    });
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
    return $self->send_response ({status => 201, status_text => 'OK'})->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d 'abcde');
      return $w->close;
    });
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
    return $self->send_response ({status => 201, status_text => 'OK'})->then (sub {
      #my $w = $self->{response}->{body}->get_writer;
      #$w->write (d 'abcde');
      #return $w->close;
    });
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
    return $self->send_response ({status => 201, status_text => 'OK'})->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d 'abcde');
      return $w->close;
    });
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
    return $self->send_response ({status => 201, status_text => 'OK'})->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d 'abcde');
    });
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
    return $self->send_response ({status => 201, status_text => 'OK'},
                                  close => 1)->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d 'abcde');
      $url = $req->{target_url};
      return $w->close;
    });
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
    return $self->send_response ({status => 201, status_text => 'OK'},
                                  close => 1)->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d 'abcde');
      $url = $req->{target_url};
      return $w->close;
    });
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
    return $self->send_response ({status => 201, status_text => 'OK'},
                                  close => 1)->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d 'abcde');
      $url = $req->{target_url};
      return $w->close;
    });
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
    return $self->send_response ({status => 201, status_text => 'OK'},
                                  close => 1)->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d 'abcde');
      $url = $req->{target_url};
      return $w->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga2'],
        ]}, close => 1)->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d 'abcde');
      $invoked++;
      return $w->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga2'],
        ]}, close => 1)->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d 'abcde');
      $invoked++;
      return $w->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'OK', headers => [
          ['Hoge', 'Fuga2'],
        ]}, close => 1)->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d 'abcde');
      $invoked++; 
      return $w->close;
    });
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
    return $self->send_response ({status => 201, status_text => 'OK'},
                                  close => 1)->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d 'abcde');
      $url = $req->{target_url};
      return $w->close;
    });
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
    return $self->send_response ({status => 201, status_text => 'OK'},
                                  close => 1)->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      $w->write (d 'abcde');
      $url = $req->{target_url};
      return $w->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'OK'}, close => 1)->then (sub {
      return $self->{response}->{body}->get_writer->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'OK'}, close => 1)->then (sub {
      return $self->{response}->{body}->get_writer->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'OK'}, close => 1)->then (sub {
      return $self->{response}->{body}->get_writer->close;
    });
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  $http->request (path => [$path])->then (sub {
    my $res = $_[0];
    test {
      is $res->header ('Server'), "Server";
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
    return $self->send_response
        ({status => 201, status_text => 'OK'}, close => 1)->then (sub {
      return $self->{response}->{body}->get_writer->close;
    });
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
    return $self->send_response
        ({status => 201, status_text => 'OK'}, close => 1)->then (sub {
      return $self->{response}->{body}->get_writer->close;
    });
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
      $self->send_response
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
      $self->send_response
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
      $self->send_response
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
} n => 2, name => 'send_response bad header name';

test {
  my $c = shift;
  my $path = rand;
  my $error;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    eval {
      $self->send_response
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
} n => 2, name => 'send_response bad header name';

test {
  my $c = shift;
  my $path = rand;
  my $error;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    eval {
      $self->send_response
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
} n => 2, name => 'send_response bad header value';

test {
  my $c = shift;
  my $path = rand;
  my $error;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    eval {
      $self->send_response
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
} n => 2, name => 'send_response bad header name';

test {
  my $c = shift;
  my $path = rand;
  my $error;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    eval {
      $self->send_response
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
} n => 2, name => 'send_response bad header value';

test {
  my $c = shift;
  my $path = rand;
  my $error;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    eval {
      $self->send_response
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
} n => 2, name => 'send_response bad status text';

test {
  my $c = shift;
  my $path = rand;
  my $error;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    eval {
      $self->send_response
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
} n => 2, name => 'send_response bad status text';

test {
  my $c = shift;
  my $path = rand;
  my $error;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    return $self->send_response
        ({status => 201, status_text => "OK"}, close => 1)->then (sub {
      return $self->send_response
            ({status => 202, status_text => "Not OK"}, close => 1);
    })->catch (sub {
      $error = $_[0];
      return $self->{response}->{body}->get_writer->close;
    });
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  $http->request (path => [$path])->then (sub {
    my $res = $_[0];
    test {
      like $error, qr{^TypeError: \|send_response\| is invoked twice at \Q@{[__FILE__]}\E line \Q@{[__LINE__-12]}\E};
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
} n => 2, name => 'send_response after headers';

test {
  my $c = shift;
  my $path = rand;
  my $error;
  $HandleRequestHeaders->{"/$path"} = sub {
    my ($self, $req) = @_;
    return $self->send_response
        ({status => 201, status_text => "OK"}, close => 1)->then (sub {
      my $w = $self->{response}->{body}->get_writer;
      return $w->close->then (sub {
        return $w->write (d "abc");
      })->catch (sub {
        $error = $_[0];
      });
    });
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  $http->request (path => [$path])->then (sub {
    my $res = $_[0];
    test {
      like $error, qr{^TypeError: WritableStream is closed at \Q@{[__FILE__]}\E line \Q@{[__LINE__-11]}\E};
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
    return $self->send_response
        ({status => 201, status_text => "OK"}, close => 1)->then (sub {
      return $self->{response}->{body}->get_writer->close;
    })->then (sub {
      return $self->send_response
          ({status => 202, status_text => "Not OK"}, close => 1);
    })->catch (sub {
      $error = $_[0];
    });
  };

  my $http = Web::Transport::ConnectionClient->new_from_url ($Origin);
  $http->request (path => [$path])->then (sub {
    my $res = $_[0];
    test {
      like $error, qr{^TypeError: \|send_response\| is invoked twice at \Q@{[__FILE__]}\E line \Q@{[__LINE__-11]}\E};
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
} n => 2, name => 'send_response after close';

Test::Certificates->wait_create_cert;
$GlobalCV->begin;
run_tests;
$GlobalCV->end;
$GlobalCV->recv;
$HandleRequestHeaders = {};

=head1 LICENSE

Copyright 2016-2017 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut