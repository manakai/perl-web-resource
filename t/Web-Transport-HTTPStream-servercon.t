use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->child ('t_deps/lib');
use lib glob path (__FILE__)->parent->parent->child ('t_deps/modules/*/lib');
use Test::X1;
use Test::More;
use AnyEvent::Socket;
use Promised::Flow;
use Web::Host;
use Web::URL;
use Web::Transport::ConnectionClient;
use Web::Transport::TCPStream;
use Web::Transport::HTTPStream;
use Web::Transport::TCPTransport;
use Web::Transport::FindPort;

sub rsread ($) {
  my $rs = shift;
  return Promise->resolve (undef) unless defined $rs;
  my $r = $rs->get_reader;
  my $run; $run = sub {
    return $r->read->then (sub {
      return if $_[0]->{done};
      if (ref $_[0]->{value} eq 'HASH' and
          defined $_[0]->{value}->{body}) {
        rsread ($_[0]->{value}->{body});
      }
      if (ref $_[0]->{value} eq 'HASH' and
          defined $_[0]->{value}->{text_body}) {
        rsread ($_[0]->{value}->{text_body});
      }
      return $run->();
    });
  }; # $run
  return $run->()->then (sub { undef $run }, sub { undef $run });
} # rsread

sub d ($) {
  return DataView->new (ArrayBuffer->new_from_scalarref (\($_[0])));
} # d

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $origin = Web::URL->parse_string ("http://$host:$port");

  my $ready1;
  my $ready2;
  my @con;
  my $server = tcp_server $host, $port, sub {
    my $x = Web::Transport::HTTPStream->new
        ({server => 1, parent => {
           class => 'Web::Transport::TCPStream',
           server => 1,
           fh => $_[0],
           host => Web::Host->parse_string ($_[1]), port => $_[2],
         }});

    $x->ready->then (sub {
      $ready1 = 1;
    }, sub {
      $ready1 = 0;
    });

    my $r = $x->streams->get_reader;
    $r->read->then (sub {
      return 0 if $_[0]->{done};
      test {
        ok $x->info->{id};
        is $x->info->{parent}->{type}, 'TCP';
        is $x->info->{type}, 'H1';
        is $x->info->{layered_type}, 'H1/TCP';
      } $c;
      $ready2 = $ready1;
      my $stream = $_[0]->{value};
      return $stream->headers_received->then (sub {
        my $path = $stream->{request}->{target_url}->path;
        test {
          ok $stream->info->{id};
          is $stream->info->{parent}, $x->info;
          is $stream->info->{type}, 'Stream';
          is $stream->info->{layered_type}, 'Stream/H1/TCP';
        } $c;
        return $stream->send_response
            ({status => 210, status_text => $stream->{id}, headers => []})->then (sub {
          return $_[0]->{body}->get_writer->close;
        });
      })->then (sub { return 1 });
    })->then (sub {
      $r->release_lock;
      return rsread $x->streams;
    });

    push @con, $x;
  }; # $server

  my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
  $client->request (path => [])->then (sub {
    my $res = $_[0];
    test {
      is $ready1, 1;
      is $ready2, 1;
    } $c;
    return $client->close;
  })->then (sub {
    return Promise->all ([map { $_->closed } @con]);
  })->then (sub {
    undef $server;
    done $c;
    undef $c;
  });
} n => 10, name => 'server connection ready promise';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $origin = Web::URL->parse_string ("http://$host:$port");

  my $ready1;
  my $closed1;
  my $error1;
  my $error2;
  my @con;
  my $server = tcp_server $host, $port, sub {
    my $x = Web::Transport::HTTPStream->new
        ({server => 1, parent => {
           class => 'Web::Transport::TCPStream',
           server => 1,
           host => Web::Host->parse_string ($_[1]), port => $_[2],
         }});

    $x->ready->then (sub {
      $ready1 = 1;
    }, sub {
      $ready1 = 0;
      $error1 = $_[0];
    });

    $x->closed->then (sub {
      $closed1 = 1;
    }, sub {
      $closed1 = 0;
      $error2 = $_[0];
    });

    rsread $x->streams;

    push @con, $x;
  }; # $server

  my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
  $client->request (path => [])->then (sub {
    my $res = $_[0];
    test {
      is $ready1, 0;
      like $error1, qr{^TypeError: Bad \|fh\| at };
      is $closed1, 1;
    } $c;
  })->then (sub {
    return Promise->all ([map { $_->closed } @con]);
  })->then (sub {
    return $client->close;
  })->then (sub {
    undef $server;
    done $c;
    undef $c;
  });
} n => 3, name => 'server connection ready promise rejected';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $origin = Web::URL->parse_string ("http://$host:$port");

  my @con;
  my $server = tcp_server $host, $port, sub {
    my $x = Web::Transport::HTTPStream->new
        ({server => 1, parent => {
           class => 'Web::Transport::TCPStream',
           server => 1,
           fh => $_[0],
           host => Web::Host->parse_string ($_[1]), port => $_[2],
         }});
    my $r = $x->streams->get_reader;
    $r->read->then (sub {
      return 0 if $_[0]->{done};
      my $stream = $_[0]->{value};
      return $stream->headers_received->then (sub {
        my $path = $stream->{request}->{target_url}->path;
        return $stream->send_response
            ({status => 210, status_text => $stream->{id}, headers => []})->then (sub {
          return $_[0]->{body}->get_writer->close;
        });
      })->then (sub { return 1 });
    })->then (sub {
      $r->release_lock;
      return rsread $x->streams;
    });

    push @con, $x;
  }; # $server

  my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
  my $id;
  $client->request (path => [])->then (sub {
    my $res = $_[0];
    test {
      $id = $con[-1]->info->{id};
      is $res->status, 210;
      like $res->status_text, qr{^\Q$id\E};
      is $res->header ('Connection'), undef;
    } $c;
    my $p = $con[-1]->close_after_current_stream;
    test {
      ok ! $con[-1]->is_active;
    } $c;
    return $p;
  })->then (sub {
    return $client->request (path => []);
  })->then (sub {
    my $res = $_[0];
    test {
      if ($res->is_network_error) {
        ok $res->is_reset_error;
        ok 1;
      } else {
        is $res->status, 210, $res;
        unlike $res->status_text, qr{^\Q$id\E};
      }
    } $c;
    return $client->close;
  })->then (sub {
    return Promise->all ([map { $_->closed } @con]);
  })->then (sub {
    undef $server;
    done $c;
    undef $c;
  });
} n => 6, name => 'server closed after request/response';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $origin = Web::URL->parse_string ("http://$host:$port");

  my $response_header_sent;
  my $after_response_header = Promise->new (sub { $response_header_sent = $_[0] });

  my $con;
  my $server = tcp_server $host, $port, sub {
    my $x = Web::Transport::HTTPStream->new
        ({server => 1, parent => {
           class => 'Web::Transport::TCPStream',
           server => 1,
           fh => $_[0],
           host => Web::Host->parse_string ($_[1]), port => $_[2],
         }});
    my $r = $x->streams->get_reader;
    $r->read->then (sub {
      return if $_[0]->{done};
      my $stream = $_[0]->{value};
      return $stream->headers_received->then (sub {
        my $path = $stream->{request}->{target_url}->path;
        if ($path eq '/404') {
          $stream->send_response
              ({status => 404, status_text => $stream->{id}, headers => []})->then (sub {
            return $_[0]->{body}->get_writer->close;
          });
        } else {
          $stream->send_response
              ({status => 210, status_text => $stream->{id}, headers => []})->then (sub {
            $response_header_sent->($_[0]);
          });
        }
      });
    })->then (sub {
      $r->release_lock;
      return rsread $x->streams;
    });

    $con ||= $x;
  }; # $server

  my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
  my $id;
  my $after_request = $client->request (path => []);
  $after_response_header->then (sub {
    my $w = $_[0]->{body}->get_writer;
    promised_sleep (1)->then (sub {
      $w->write (d "abcde");
      return $w->close;
    });
    return $con->close_after_current_stream;
  })->then (sub {
    return $after_request;
  })->then (sub {
    my $res = $_[0];
    test {
      $id = $con->info->{id};
      is $res->status, 210;
      like $res->status_text, qr{^\Q$id\E};
      is $res->header ('Connection'), undef;
      is $res->body_bytes, "abcde";
    } $c;
  })->then (sub {
    return $client->request (path => ['404']);
  })->then (sub {
    my $res = $_[0];
    test {
      is $res->status, 404;
      unlike $res->status_text, qr{^\Q$id\E};
    } $c;
    return $client->close;
  })->then (sub {
    return $con->closed;
  })->then (sub {
    undef $server;
    done $c;
    undef $c;
  });
} n => 6, name => 'server closed during response';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $origin = Web::URL->parse_string ("http://$host:$port");

  my $response_header_sent;
  my $after_response_header = Promise->new (sub { $response_header_sent = $_[0] });

  my $con;
  my $server = tcp_server $host, $port, sub {
    my $x = Web::Transport::HTTPStream->new
        ({server => 1, parent => {
           class => 'Web::Transport::TCPStream',
           server => 1,
           fh => $_[0],
           host => Web::Host->parse_string ($_[1]), port => $_[2],
         }});
    my $r = $x->streams->get_reader;
    $r->read->then (sub {
      return if $_[0]->{done};
      my $stream = $_[0]->{value};
      return $stream->headers_received->then (sub {
        my $path = $stream->{request}->{target_url}->path;
        if ($path eq '/404') {
          $stream->send_response
              ({status => 404, status_text => $stream->{id}, headers => []})->then (sub {
            return $_[0]->{body}->get_writer->close;
          });
        } else {
          $response_header_sent->($stream);
        }
      });
    })->then (sub {
      $r->release_lock;
      return rsread $x->streams;
    });
    $con ||= $x;
  }; # $server

  my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
  my $id;
  my $after_request = $client->request (path => []);
  $after_response_header->then (sub {
    my $stream = $_[0];
    promised_sleep (1)->then (sub {
      return $stream->send_response
          ({status => 210, status_text => $stream->{id}, headers => []})->then (sub {
        my $w = $_[0]->{body}->get_writer;
        $w->write (d "abcde");
        return $w->close;
      });
    });
    return $con->close_after_current_stream;
  })->then (sub {
    return $after_request;
  })->then (sub {
    my $res = $_[0];
    test {
      $id = $con->info->{id};
      is $res->status, 210;
      is $res->header ('Connection'), 'close';
      like $res->status_text, qr{^\Q$id\E};
      is $res->body_bytes, "abcde";
    } $c;
  })->then (sub {
    return $client->request (path => ['404']);
  })->then (sub {
    my $res = $_[0];
    test {
      is $res->status, 404;
      unlike $res->status_text, qr{^\Q$id\E};
    } $c;
    return $client->close;
  })->then (sub {
    return $con->closed;
  })->then (sub {
    undef $server;
    done $c;
    undef $c;
  });
} n => 6, name => 'server closed before response';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $origin = Web::URL->parse_string ("http://$host:$port");

  my @con;
  my $p;
  my $server = tcp_server $host, $port, sub {
    my $x = Web::Transport::HTTPStream->new
        ({server => 1, parent => {
           class => 'Web::Transport::TCPStream',
           server => 1,
           fh => $_[0],
           host => Web::Host->parse_string ($_[1]), port => $_[2],
         }});

    $p = $x->send_request ({method => 'GET', target => '/'});
    rsread $x->streams;
    push @con, $x;
  }; # $server

  my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
  $client->request (path => []);
  (promised_wait_until { !! $p })->then (sub {
    test {
      isa_ok $p, 'Promise';
    } $c;
    return $p;
  })->catch (sub {
    my $error = $_[0];
    test {
      is $error->name, 'TypeError';
      is $error->message, 'Request is not allowed';
      is $error->file_name, __FILE__;
      is $error->line_number, __LINE__-18;
    } $c;
    return $client->abort;
  })->then (sub {
    return Promise->all ([map { $_->abort } @con]);
  })->then (sub {
    undef $server;
    test {
      ok 1;
    } $c;
    done $c;
    undef $c;
  });
} n => 6, name => 'send_request on server connection';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $origin = Web::URL->parse_string ("http://$host:$port");

  my $p;
  my @con;
  my $server = tcp_server $host, $port, sub {
    my $x = Web::Transport::HTTPStream->new
        ({server => 1, parent => {
           class => 'Web::Transport::TCPStream',
           server => 1,
           fh => $_[0],
           host => Web::Host->parse_string ($_[1]), port => $_[2],
         }});

    $p = $x->close_after_current_stream->then (sub {
      test {
        ok 1;
      } $c;
    }, sub {
      my $error = $_[0];
      test {
        ok 0, $error;
      } $c;
    });
    test {
      ok ! $x->is_active, 'connection not ready';
    } $c;

    $x->ready->then (sub {
      test {
        ok $x->is_active, 'connection ready';
      } $c;

      $x->abort;
      rsread $x->streams;

      push @con, $x;
    });
  }; # $server

  my $client = Web::Transport::ConnectionClient->new_from_url ($origin);
  $client->request (path => [])->then (sub {
    my $res = $_[0];
    return $p;
  })->then (sub {
    return $client->abort;
  })->then (sub {
    undef $server;
    done $c;
    undef $c;
  });
} n => 3, name => 'close_after_current_stream-';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $origin = Web::URL->parse_string ("http://$host:$port");

  my $con;
  my $server = tcp_server $host, $port, sub {
    my $x = Web::Transport::HTTPStream->new
        ({server => 1, parent => {
           class => 'Web::Transport::TCPStream',
           server => 1,
           fh => $_[0],
           host => Web::Host->parse_string ($_[1]), port => $_[2],
         }, server_header => 'Hoge/1.4.6'});
    my $r = $x->streams->get_reader;
    $r->read->then (sub {
      return if $_[0]->{done};
      my $stream = $_[0]->{value};
      return $stream->headers_received->then (sub {
        return $stream->send_response
            ({status => 201, status_text => 'OK', close => 1, length => 0, headers => []});
      });
    })->then (sub {
      $r->release_lock;
      return rsread $x->streams;
    });
    $con ||= $x;
  }; # $server

  my $http = Web::Transport::ConnectionClient->new_from_url ($origin);
  $http->request (path => [])->then (sub {
    my $res = $_[0];
    test {
      is $res->header ('Server'), undef;
    } $c;
  })->then (sub {
    return $http->close;
  })->then (sub {
    return $con->closed;
  })->then (sub {
    undef $server;
    done $c;
    undef $c;
  });
} n => 1, name => '$con->server_header';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $origin = Web::URL->parse_string ("http://$host:$port");

  my $con;
  my $server = tcp_server $host, $port, sub {
    my $x = Web::Transport::HTTPStream->new
        ({server => 1, parent => {
           class => 'Web::Transport::TCPStream',
           server => 1,
           fh => $_[0],
           host => Web::Host->parse_string ($_[1]), port => $_[2],
         }, server_header => "\x{3000}a\x00"});
    my $r = $x->streams->get_reader;
    $r->read->then (sub {
      return if $_[0]->{done};
      my $stream = $_[0]->{value};
      return $stream->headers_received->then (sub {
        return $stream->send_response
            ({status => 201, status_text => 'OK', close => 1, length => 0, headers => []});
      });
    })->then (sub {
      $r->release_lock;
      return rsread $x->streams;
    });
    $con ||= $x;
  }; # $server

  my $http = Web::Transport::ConnectionClient->new_from_url ($origin);
  $http->request (path => [])->then (sub {
    my $res = $_[0];
    test {
      is $res->header ('Server'), undef;
    } $c;
  })->then (sub {
    return $http->close;
  })->then (sub {
    return $con->closed;
  })->then (sub {
    undef $server;
    done $c;
    undef $c;
  });
} n => 1, name => '$con->server_header';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $origin = Web::URL->parse_string ("http://$host:$port");

  my $con;
  my $server = tcp_server $host, $port, sub {
    my $x = Web::Transport::HTTPStream->new
        ({server => 1, parent => {
           class => 'Web::Transport::TCPStream',
           server => 1,
           fh => $_[0],
           host => Web::Host->parse_string ($_[1]), port => $_[2],
         }, server_header => ""});
    my $r = $x->streams->get_reader;
    $r->read->then (sub {
      return if $_[0]->{done};
      my $stream = $_[0]->{value};
      return $stream->headers_received->then (sub {
        return $stream->send_response
            ({status => 201, status_text => 'OK', close => 1, length => 0, headers => []});
      });
    })->then (sub {
      $r->release_lock;
      return rsread $x->streams;
    });
    $con ||= $x;
  }; # $server

  my $http = Web::Transport::ConnectionClient->new_from_url ($origin);
  $http->request (path => [])->then (sub {
    my $res = $_[0];
    test {
      is $res->header ('Server'), undef;
    } $c;
  })->then (sub {
    return $http->close;
  })->then (sub {
    return $con->closed;
  })->then (sub {
    undef $server;
    done $c;
    undef $c;
  });
} n => 1, name => '$con->server_header';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $origin = Web::URL->parse_string ("http://$host:$port");

  my $con;
  my $server = tcp_server $host, $port, sub {
    my $x = Web::Transport::HTTPStream->new
        ({server => 1, parent => {
           class => 'Web::Transport::TCPStream',
           server => 1,
           fh => $_[0],
           host => Web::Host->parse_string ($_[1]), port => $_[2],
         }, server_header => "0"});
    my $r = $x->streams->get_reader;
    $r->read->then (sub {
      return if $_[0]->{done};
      my $stream = $_[0]->{value};
      return $stream->headers_received->then (sub {
        return $stream->send_response
            ({status => 201, status_text => 'OK', close => 1, length => 0, headers => []});
      });
    })->then (sub {
      $r->release_lock;
      return rsread $x->streams;
    });
    $con ||= $x;
  }; # $server

  my $http = Web::Transport::ConnectionClient->new_from_url ($origin);
  $http->request (path => [])->then (sub {
    my $res = $_[0];
    test {
      is $res->header ('Server'), undef;
    } $c;
  })->then (sub {
    return $http->close;
  })->then (sub {
    return $con->closed;
  })->then (sub {
    undef $server;
    done $c;
    undef $c;
  });
} n => 1, name => '$con->server_header';

test {
  my $c = shift;

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $origin = Web::URL->parse_string ("http://$host:$port");

  my $server = tcp_server $host, $port, sub {
    my $x = Web::Transport::HTTPStream->new
        ({server => 1, parent => {
           class => 'Web::Transport::TCPStream',
           server => 1,
           fh => $_[0],
           host => Web::Host->parse_string ($_[1]), port => $_[2],
         }});
    my $r = $x->streams->get_reader;
    $x->ready->then (sub {
      $r->cancel;
    });
  }; # $server

  my $http = Web::Transport::ConnectionClient->new_from_url ($origin);
  $http->request (path => [])->then (sub {
    my $res = $_[0];
    test {
      ok $res->is_network_error;
    } $c;
  })->then (sub {
    return $http->close;
  })->then (sub {
    undef $server;
    done $c;
    undef $c;
  });
} n => 1, name => 'streams cancel';

sub rawtcp ($$$) {
  my $input = $_[2];
  my $tcp = Web::Transport::TCPTransport->new (host => $_[0], port => $_[1]);
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

  my $host = '127.0.0.1';
  my $port = find_listenable_port;
  my $origin = Web::URL->parse_string ("http://$host:$port");

  my $closed;
  my $server = tcp_server $host, $port, sub {
    my $x = Web::Transport::HTTPStream->new
        ({server => 1, parent => {
           class => 'Web::Transport::TCPStream',
           server => 1,
           fh => $_[0],
           host => Web::Host->parse_string ($_[1]), port => $_[2],
         }});
    my $r = $x->streams->get_reader;
    $r->read->then (sub {
      return $_[0]->{value}->closed;
    })->then (sub {
      $closed = $_[0];
    });
  }; # $server

  rawtcp ($origin->host, $origin->port, "GET foo HTTP/1.0\x0D\x0A\x0D\x0A")->then (sub {
    test {
      isa_ok $closed, 'Web::Transport::ProtocolError::HTTPParseError';
      is $closed->name, 'HTTP parse error';
      is $closed->message, 'Bad request-target';
      is $closed->file_name, __FILE__;
      is $closed->line_number, __LINE__-21;
      ok $closed->http_fatal;
      ok ! $closed->http_can_retry;
    } $c;
  })->then (sub {
    undef $server;
    done $c;
    undef $c;
  });
} n => 7, name => 'HTTP parse error';

run_tests;

=head1 LICENSE

Copyright 2016-2017 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
