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
use AnyEvent::Socket;
use Web::Transport::BasicClient;
use Web::Host;
use Web::URL;
use Web::Transport::ConstProxyManager;
use Web::Transport::PSGIServerConnection;
use Time::Local qw(timegm_nocheck);

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
  server_as_cv (q{
    "HTTP/1.1 201 o.k."CRLF
    "Hoge: foo"CRLF
    CRLF
    "abc"
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}/});
    my $client = Web::Transport::BasicClient->new_from_url ($url);
    return $client->request (url => $url, stream => 1)->then (sub {
      my $result = $_[0];
      test {
        isa_ok $result, 'Web::Transport::Response';
        ok ! $result->is_network_error;
        is $result->status, 201;
        is $result->status_text, 'o.k.';
        is $result->header ('Hoge'), 'foo';
        isa_ok $result->body_stream, 'ReadableStream';
      } $c;
      my $got = '';
      my $reader = $result->body_stream->get_reader ('byob');
      my $read; $read = sub {
        return $reader->read (DataView->new (ArrayBuffer->new (1)))->then (sub {
          return if $_[0]->{done};
          $got .= $_[0]->{value}->manakai_to_string;
          return $read->();
        });
      }; # $read
      return $read->()->then (sub { undef $read; return $got });
    })->then (sub {
      my $got = $_[0];
      test {
        is $got, "abc";
      } $c;
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 7, name => 'normal response with stream';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET"
    "HTTP/1.1 201 o.k."CRLF
    "Hoge: foo"CRLF
    "Content-length: 3"CRLF
    CRLF
    "abc"
    receive "GET"
    "HTTP/1.1 202 good"CRLF
    "Hoge: bar"CRLF
    CRLF
    "XYZ"
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}/});
    my $client = Web::Transport::BasicClient->new_from_url ($url);
    my $req1 = $client->request (url => $url, stream => 1);
    my $req2 = $client->request (url => $url, stream => 1);
    $req1->then (sub {
      my $result = $_[0];
      test {
        isa_ok $result, 'Web::Transport::Response';
        ok ! $result->is_network_error;
        is $result->status, 201;
        is $result->status_text, 'o.k.';
        is $result->header ('Hoge'), 'foo';
        isa_ok $result->body_stream, 'ReadableStream';
      } $c;
      my $got = '';
      my $reader = $result->body_stream->get_reader ('byob');
      my $read; $read = sub {
        return $reader->read (DataView->new (ArrayBuffer->new (1)))->then (sub {
          return if $_[0]->{done};
          $got .= $_[0]->{value}->manakai_to_string;
          return $read->();
        });
      }; # $read
      return $read->()->then (sub { undef $read; return $got });
    })->then (sub {
      my $got = $_[0];
      test {
        is $got, "abc";
      } $c;
      return $req2;
    })->then (sub {
      my $result = $_[0];
      test {
        isa_ok $result, 'Web::Transport::Response';
        ok ! $result->is_network_error;
        is $result->status, 202;
        is $result->status_text, 'good';
        is $result->header ('Hoge'), 'bar';
        isa_ok $result->body_stream, 'ReadableStream';
      } $c;
      my $got = '';
      my $reader = $result->body_stream->get_reader ('byob');
      my $read; $read = sub {
        return $reader->read (DataView->new (ArrayBuffer->new (1)))->then (sub {
          return if $_[0]->{done};
          $got .= $_[0]->{value}->manakai_to_string;
          return $read->();
        });
      }; # $read
      return $read->()->then (sub { undef $read; return $got });
    })->then (sub {
      my $got = $_[0];
      test {
        is $got, 'XYZ';
      } $c;
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 14, name => 'second response with stream';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET"
    "HTTP/1.1 201 o.k."CRLF
    "Hoge: foo"CRLF
    "Content-length: 3"CRLF
    CRLF
    "abc"
    receive "GET"
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}/});
    my $client = Web::Transport::BasicClient->new_from_url ($url);
    my $req1 = $client->request (url => $url, stream => 1);
    my $req2 = $client->request (url => $url, stream => 1);
    $req1->then (sub {
      my $result = $_[0];
      test {
        isa_ok $result, 'Web::Transport::Response';
        ok ! $result->is_network_error;
        is $result->status, 201;
        is $result->status_text, 'o.k.';
        is $result->header ('Hoge'), 'foo';
        isa_ok $result->body_stream, 'ReadableStream';
      } $c;
      my $got = '';
      my $reader = $result->body_stream->get_reader ('byob');
      my $read; $read = sub {
        return $reader->read (DataView->new (ArrayBuffer->new (1)))->then (sub {
          return if $_[0]->{done};
          $got .= $_[0]->{value}->manakai_to_string;
          return $read->();
        });
      }; # $read
      return $read->()->then (sub { undef $read; return $got });
    })->then (sub {
      my $got = $_[0];
      test {
        is $got, "abc";
      } $c;
      return $req2;
    })->then (sub {
      my $result = $_[0];
      test {
        isa_ok $result, 'Web::Transport::Response';
        ok ! $result->is_network_error;
        is $result->status, 201;
        is $result->status_text, 'o.k.';
        is $result->header ('Hoge'), 'foo';
        isa_ok $result->body_stream, 'ReadableStream';
      } $c;
      my $got = '';
      my $reader = $result->body_stream->get_reader ('byob');
      my $read; $read = sub {
        return $reader->read (DataView->new (ArrayBuffer->new (1)))->then (sub {
          return if $_[0]->{done};
          $got .= $_[0]->{value}->manakai_to_string;
          return $read->();
        });
      }; # $read
      return $read->()->then (sub { undef $read; return $got });
    })->then (sub {
      my $got = $_[0];
      test {
        is $got, 'abc';
      } $c;
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 14, name => 'second response failed';

test {
  my $c = shift;
  server_as_cv (q{
    receive "GET"
    "HTTP/1.1 201 o.k."CRLF
    "Hoge: foo"CRLF
    "Content-length: 3"CRLF
    CRLF
    "abc"
    receive "GET"
    "HTTP/1.1 202 good"CRLF
    "Hoge: bar"CRLF
    CRLF
    "XYZ"
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}/});
    my $client = Web::Transport::BasicClient->new_from_url ($url);
    my $req1 = $client->request (url => $url, stream => 1);
    my $req2 = $client->request (url => $url, stream => 1);
    $req1->then (sub {
      my $result = $_[0];
      test {
        isa_ok $result, 'Web::Transport::Response';
        ok ! $result->is_network_error;
        is $result->status, 201;
        is $result->status_text, 'o.k.';
        is $result->header ('Hoge'), 'foo';
        isa_ok $result->body_stream, 'ReadableStream';
      } $c;
      $result->body_stream->cancel;
      return $req2;
    })->catch (sub {
      my $result = $_[0];
      test {
        isa_ok $result, 'Web::Transport::Response';
        ok $result->is_network_error;
        is $result->network_error_message, "Something's wrong";
        is $result->body_bytes, undef;
        is $result->content, '';
        ok $result->as_string;
      } $c;
      $result->body_stream;
    })->catch (sub {
      my $error = $_[0];
      test {
        is $error->name, 'TypeError';
        is $error->message, '|body_stream| is not available';
      } $c;
      return $client->request (url => $url);
    })->then (sub {
      my $result = $_[0];
      test {
        ok ! $result->is_network_error;
        is $result->status, 201;
      } $c;
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 16, name => 'second response canceled';

test {
  my $c = shift;
  server_as_cv (q{
    "HTTP/1.1 304 o.k."CRLF
    "Hoge: foo"CRLF
    CRLF
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}/});
    my $client = Web::Transport::BasicClient->new_from_url ($url);
    return $client->request (url => $url, stream => 1)->then (sub {
      my $result = $_[0];
      test {
        isa_ok $result, 'Web::Transport::Response';
        ok ! $result->is_network_error;
        is $result->status, 304;
        is $result->status_text, 'o.k.';
        is $result->header ('Hoge'), 'foo';
        isa_ok $result->body_stream, 'ReadableStream';
      } $c;
      my $got = '';
      my $reader = $result->body_stream->get_reader ('byob');
      my $read; $read = sub {
        return $reader->read (DataView->new (ArrayBuffer->new (1)))->then (sub {
          return if $_[0]->{done};
          $got .= $_[0]->{value}->manakai_to_string;
          return $read->();
        });
      }; # $read
      return $read->()->then (sub { undef $read; return $got });
    })->then (sub {
      my $got = $_[0];
      test {
        is $got, '';
      } $c;
      return $client->close;
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 7, name => '304 response';

test {
  my $c = shift;
  server_as_cv (q{
    "HTTP/1.1 201 o.k."CRLF
    "Hoge: foo"CRLF
    CRLF
    "abc"
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}/});
    my $client = Web::Transport::BasicClient->new_from_url ($url);
    return $client->request (url => $url, stream => 1)->then (sub {
      my $result = $_[0];
      return Promise->resolve->then (sub {
        $result->body_bytes;
      })->catch (sub {
        my $error = $_[0];
        test {
          is $error->name, 'TypeError';
          is $error->message, '|body_bytes| is not available';
        } $c;
        $result->body_stream->cancel;
        return $client->close;
      });
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => 'stream response, normal body method';

test {
  my $c = shift;
  server_as_cv (q{
    "HTTP/1.1 201 o.k."CRLF
    "Hoge: foo"CRLF
    CRLF
    "abc"
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}/});
    my $client = Web::Transport::BasicClient->new_from_url ($url);
    return $client->request (url => $url, stream => 1)->then (sub {
      my $result = $_[0];
      return Promise->resolve->then (sub {
        $result->content;
      })->catch (sub {
        my $error = $_[0];
        test {
          is $error->name, 'TypeError';
          is $error->message, '|body_bytes| is not available';
        } $c;
        $result->body_stream->cancel;
        return $client->close;
      });
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => 'stream response, normal body method 2';

test {
  my $c = shift;
  server_as_cv (q{
    "HTTP/1.1 201 o.k."CRLF
    "Hoge: foo"CRLF
    CRLF
    "abc"
    close
  })->cb (sub {
    my $server = $_[0]->recv;
    my $url = Web::URL->parse_string (qq{http://$server->{host}:$server->{port}/});
    my $client = Web::Transport::BasicClient->new_from_url ($url);
    return $client->request (url => $url, stream => 1)->then (sub {
      my $result = $_[0];
      return Promise->resolve->then (sub {
        $result->as_string;
      })->catch (sub {
        my $error = $_[0];
        test {
          is $error->name, 'TypeError';
          is $error->message, '|body_bytes| is not available';
        } $c;
        $result->body_stream->cancel;
        return $client->close;
      });
    })->then (sub {
      done $c;
      undef $c;
    });
  });
} n => 2, name => 'stream response, normal body method 3';

Test::Certificates->wait_create_cert;
run_tests;

=head1 LICENSE

Copyright 2016-2017 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
