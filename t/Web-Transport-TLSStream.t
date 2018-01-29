use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->child ('t_deps/lib');
use lib glob path (__FILE__)->parent->parent->child ('t_deps/modules/*/lib');
use Test::More;
use Test::X1;
use Test::Certificates;
use Web::Host;
use DataView;
use ArrayBuffer;
use Promised::Flow;
use AnyEvent::Socket qw(tcp_server);
use Web::Transport::TCPStream;
use Web::Transport::TLSStream;
use AbortController;

sub dv ($) {
  return DataView->new (ArrayBuffer->new_from_scalarref (\($_[0])));
} # dv

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

{
  package test::DestroyCallback1;
  sub DESTROY {
    $_[0]->();
  }
}

sub create_tls_server ($$$) {
  return Web::Transport::TLSStream->create ({
    server => 1,
      ca_file => Test::Certificates->ca_path ('cert.pem'),
      cert_file => Test::Certificates->cert_path ('cert-chained.pem'),
      key_file => Test::Certificates->cert_path ('key.pem'),
      parent => {
        class => 'Web::Transport::TCPStream',
        server => 1,
        fh => $_[0],
        host => Web::Host->parse_string ($_[1]),
        port => $_[2],
      },
    });
} # create_tls_server

sub create_tls_client ($$) {
  return Web::Transport::TLSStream->create ({
    sni_host => Web::Host->parse_string (Test::Certificates->cert_name),
    si_host => Web::Host->parse_string (Test::Certificates->cert_name),
    ca_file => Test::Certificates->ca_path ('cert.pem'),
    parent => {
      class => 'Web::Transport::TCPStream',
      host => $_[0],
      port => $_[1],
    },
  });
} # create_tls_client

test {
  my $c = shift;
  Web::Transport::TLSStream->create ({
    ca_file => Test::Certificates->ca_path ('cert.pem'),
    parent => {
      class => 'Web::Transport::TCPStream',
      host => Web::Host->parse_string ('127.0.0.44'),
      port => 41333,
    },
  })->catch (sub {
    my $e = $_[0];
    test {
      is $e->name, 'TypeError';
      is $e->message, 'Bad |host|';
      is $e->file_name, __FILE__;
      is $e->line_number, __LINE__+4;
    } $c;
    done $c;
    undef $c;
  });
} n => 4, name => 'Bad |host|';

test {
  my $c = shift;
  Web::Transport::TLSStream->create ({
    host => Web::Host->parse_string (Test::Certificates->cert_name),
    ca_file => Test::Certificates->ca_path ('cert.pem'),
  })->catch (sub {
    my $e = $_[0];
    test {
      is $e->name, 'TypeError';
      is $e->message, 'Bad |parent|';
      is $e->file_name, __FILE__;
      is $e->line_number, __LINE__+4;
    } $c;
    done $c;
    undef $c;
  });
} n => 4, name => 'Bad |parent|';

test {
  my $c = shift;
  Web::Transport::TLSStream->create ({
    host => Web::Host->parse_string (Test::Certificates->cert_name),
    ca_file => Test::Certificates->ca_path ('cert.pem'),
    parent => {},
  })->catch (sub {
    my $e = $_[0];
    test {
      is $e->name, 'TypeError';
      is $e->message, 'Bad |parent|';
      is $e->file_name, __FILE__;
      is $e->line_number, __LINE__+4;
    } $c;
    done $c;
    undef $c;
  });
} n => 4, name => 'Bad |parent|';

test {
  my $c = shift;

  my $port = find_listenable_port;
  my $host = Web::Host->parse_string ('127.0.0.1');

  my $destroyed = 0;

  my $server = tcp_server undef, $port, sub {
    create_tls_server ($_[0], $_[1], $_[2])->then (sub {
      my $info = $_[0];

      my $w = $info->{writable}->get_writer;
      my $r = $info->{readable}->get_reader;

      $info->{readable}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';
      $info->{writable}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';

      $w->write (dv "abc");
      $w->write (dv "xyz");
      $w->close;

    });
  }; # $server

  create_tls_client ($host, $port)->then (sub {
    my $info = $_[0];
    my $w = $info->{writable}->get_writer;
    my $r = $info->{readable}->get_reader ('byob');
    my @result;

    $info->{readable}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';
    $info->{writable}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';

    my $try; $try = sub {
      return $r->read (dv "x" x 10)->then (sub {
        my $v = $_[0];
        return if $v->{done};
        push @result, $v->{value};
        return $try->();
      });
    };

    $w->close;

    return $try->()->then (sub {
      my $result = join '', map {
        $_->manakai_to_string;
      } @result;
      test {
        is $result, "abcxyz";
      } $c;
      undef $try;
    });
  })->catch (sub {
    my $e = $_[0];
    test {
      ok 0, $e;
    } $c;
  })->then (sub {
    return promised_wait_until { $destroyed == 4 } timeout => 3;
  })->then (sub {
    test {
      is $destroyed, 4;
    } $c;
    done $c;
    undef $c;
    undef $server;
  });
} n => 2, name => 'a server returning constant data byob 1';

test {
  my $c = shift;

  my $port = find_listenable_port;
  my $host = Web::Host->parse_string ('127.0.0.1');

  my $destroyed = 0;
  my $server = tcp_server undef, $port, sub {
    create_tls_server ($_[0], $_[1], $_[2])->then (sub {
      my $info = $_[0];

      my $w = $info->{writable}->get_writer;
      my $r = $info->{readable}->get_reader;

      $info->{readable}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';
      $info->{writable}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';

      $w->write (dv "abc");
      $w->write (dv "xyz");
      $w->close;

    });
  }; # $server

  create_tls_client ($host, $port)->then (sub {
    my $info = $_[0];
    my $w = $info->{writable}->get_writer;
    my $r = $info->{readable}->get_reader ('byob');
    my @result;

    $info->{readable}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';
    $info->{writable}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';

    $r->read (dv "x" x 10)->then (sub {
      my $v = $_[0];
      push @result, $v->{value} unless $v->{done};
    });

    my $try; $try = sub {
      return $r->read (dv "x" x 10)->then (sub {
        my $v = $_[0];
        return if $v->{done};
        push @result, $v->{value};
        return $try->();
      });
    };

    $w->close;

    return $try->()->then (sub {
      my $result = join '', map {
        $_->manakai_to_string;
      } @result;
      test {
        is $result, "abcxyz";
      } $c;
      undef $try;
    });
  })->catch (sub {
    my $e = $_[0];
    test {
      ok 0, $e;
    } $c;
  })->then (sub {
    return promised_wait_until { $destroyed == 4 } timeout => 3;
  })->then (sub {
    test {
      is $destroyed, 4;
    } $c;
    done $c;
    undef $c;
    undef $server;
  });
} n => 2, name => 'a server returning constant data byob 2';

test {
  my $c = shift;

  my $port = find_listenable_port;
  my $host = Web::Host->parse_string ('127.0.0.1');

  my @s;
  my @c;

  my $destroyed = 0;
  my $server = tcp_server undef, $port, sub {
    create_tls_server ($_[0], $_[1], $_[2])->then (sub {
      my $info = $_[0];

      my $w = $info->{writable}->get_writer;
      my $r = $info->{readable}->get_reader;

      $info->{readable}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';
      $info->{writable}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';

      $w->write (dv "abc");
      $w->write (dv "xyz");
      $w->close;

      $r->closed->then (sub {
        push @s, 'r close';
      });
      $w->closed->then (sub {
        push @s, 'w close';
      });
      promised_wait_until { $r->read->then (sub { $_[0]->{done} }) };
      $info->{closed}->then (sub {
        push @s, 'i close';
      });
    });
  }; # $server

  create_tls_client ($host, $port)->then (sub {
    my $info = $_[0];
    my $w = $info->{writable}->get_writer;
    my $r = $info->{readable}->get_reader ('byob');
    my @result;

    $info->{readable}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';
    $info->{writable}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';

    $r->read (dv "x" x 10)->then (sub {
      my $v = $_[0];
      push @result, $v->{value} unless $v->{done};
    });

    my $try; $try = sub {
      return $r->read (dv "x" x 10)->then (sub {
        my $v = $_[0];
        return if $v->{done};
        push @result, $v->{value};
        return $try->();
      });
    };

    $w->close;

    $r->closed->then (sub { push @c, 'r close' });
    $w->closed->then (sub { push @c, 'w close' });
    $info->{closed}->then (sub { push @c, 'i close' });

    return $try->()->then (sub {
      my $result = join '', map {
        $_->manakai_to_string;
      } @result;
      test {
        is $result, "abcxyz";
      } $c;
      undef $try;
    });
  })->catch (sub {
    my $e = $_[0];
    test {
      ok 0, $e;
    } $c;
  })->then (sub {
    return promised_wait_until { $destroyed == 4 and @s >= 3 and @c >= 3 } timeout => 3;
  })->then (sub {
    test {
      is $destroyed, 4;
      is 0+@s, 3;
      like $s[0], qr{^[wr] close$};
      like $s[1], qr{^[wr] close$};
      is $s[2], "i close";
      is 0+@c, 3;
      like $c[0], qr{^[wr] close$};
      like $c[1], qr{^[wr] close$};
      is $c[2], "i close";
    } $c;
    done $c;
    undef $c;
    undef $server;
  });
} n => 10, name => 'a server returning constant data byob 3';

test {
  my $c = shift;

  my $port = find_listenable_port;
  my $host = Web::Host->parse_string ('127.0.0.1');

  my $destroyed = 0;
  my $server = tcp_server undef, $port, sub {
    create_tls_server ($_[0], $_[1], $_[2])->then (sub {
      my $info = $_[0];

      my $w = $info->{writable}->get_writer;
      my $r = $info->{readable}->get_reader;

      $info->{readable}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';
      $info->{writable}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';

      $w->write (dv "abc");
      $w->write (dv "xyz");
      $w->close;

    });
  }; # $server

  create_tls_client ($host, $port)->then (sub {
    my $info = $_[0];
    my $w = $info->{writable}->get_writer;
    my $r = $info->{readable}->get_reader;

    $info->{readable}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';
    $info->{writable}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';

    my @result;

    $r->read->then (sub {
      my $v = $_[0];
      push @result, $v->{value} unless $v->{done};
    });

    my $try; $try = sub {
      return $r->read->then (sub {
        my $v = $_[0];
        return if $v->{done};
        push @result, $v->{value};
        return $try->();
      });
    };

    $w->close;

    return $try->()->then (sub {
      my $result = join '', map {
        my $dv = DataView->new ($_->buffer, $_->byte_offset, $_->byte_length);
        $dv->manakai_to_string;
      } @result;
      test {
        is $result, "abcxyz";
      } $c;
      undef $try;
    });
  })->then (sub {
    return promised_wait_until { $destroyed == 4 } timeout => 3;
  })->then (sub {
    test {
      is $destroyed, 4;
    } $c;
  })->catch (sub {
    my $e = $_[0];
    test {
      ok 0, $e;
    } $c;
  })->then (sub {
    done $c;
    undef $c;
    undef $server;
  });
} n => 2, name => 'a server returning constant data default 2';

test {
  my $c = shift;

  my $port = find_listenable_port;
  my $host = Web::Host->parse_string ('127.0.0.1');

  my $destroyed;
  my $server = tcp_server undef, $port, sub {
    create_tls_server ($_[0], $_[1], $_[2])->then (sub {
      my $info = $_[0];

      my $w = $info->{writable}->get_writer;
      my $r = $info->{readable}->get_reader ('byob');

      $info->{readable}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';
      $info->{writable}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';

      my $read; $read = sub {
        return $r->read (dv "x" x 10)->then (sub {
          if ($_[0]->{done}) {
            $w->close;
            return;
          }
          $w->write ($_[0]->{value});
          return $read->();
        });
      };
      return $read->()->then (sub { undef $read });
    });
  }; # $server

  create_tls_client ($host, $port)->then (sub {
    my $info = $_[0];
    my $w = $info->{writable}->get_writer;
    my $r = $info->{readable}->get_reader ('byob');

    $info->{readable}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';
    $info->{writable}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';

    $w->write (dv "abcdef");
    $w->write (dv "foo bar 123");
    $w->close;

    my @result;
    my $try; $try = sub {
      return $r->read (dv "x" x 10)->then (sub {
        my $v = $_[0];
        return if $v->{done};
        push @result, $v->{value};
        return $try->();
      });
    };

    return $try->()->then (sub {
      my $result = join '', map {
        $_->manakai_to_string;
      } @result;
      test {
        is $result, "abcdeffoo bar 123";
      } $c;
      undef $try;
    });
  })->catch (sub {
    my $e = $_[0];
    test {
      ok 0, $e;
    } $c;
  })->then (sub {
    return promised_wait_until { $destroyed == 4 } timeout => 3;
  })->then (sub {
    test {
      is $destroyed, 4;
    } $c;
    done $c;
    undef $c;
    undef $server;
  });
} n => 2, name => 'an echo server (byob)';

test {
  my $c = shift;

  my $port = find_listenable_port;
  my $host = Web::Host->parse_string ('127.0.0.1');

  my $destroyed = 0;
  my $server = tcp_server undef, $port, sub {
    create_tls_server ($_[0], $_[1], $_[2])->then (sub {
      my $info = $_[0];

      my $w = $info->{writable}->get_writer;
      my $r = $info->{readable}->get_reader ('byob');

      $info->{readable}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';
      $info->{writable}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';

      my $read; $read = sub {
        return $r->read (dv "x" x 10)->then (sub {
          if ($_[0]->{done}) {
            $w->close;
            return;
          }
          $w->write ($_[0]->{value});
          return $read->();
        });
      };
      return $read->()->then (sub { undef $read });
    });
  }; # $server

  create_tls_client ($host, $port)->then (sub {
    my $info = $_[0];
    my $w = $info->{writable}->get_writer;
    my $r = $info->{readable}->get_reader;

    $info->{readable}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';
    $info->{writable}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';

    $w->write (dv "abcdef");
    $w->write (dv "foo bar 123");
    $w->close;

    my @result;
    my $try; $try = sub {
      return $r->read->then (sub {
        my $v = $_[0];
        return if $v->{done};
        push @result, $v->{value};
        return $try->();
      });
    };

    return $try->()->then (sub {
      my $result = join '', map {
        my $dv = DataView->new ($_->buffer, $_->byte_offset, $_->byte_length);
        $dv->manakai_to_string;
      } @result;
      test {
        is $result, "abcdeffoo bar 123";
      } $c;
      undef $try;
    });
  })->catch (sub {
    my $e = $_[0];
    test {
      ok 0, $e;
    } $c;
  })->then (sub {
    return promised_wait_until { $destroyed == 4 } timeout => 3;
  })->then (sub {
    test {
      is $destroyed, 4;
    } $c;
    done $c;
    undef $c;
    undef $server;
  });
} n => 2, name => 'an echo server (default)';

test {
  my $c = shift;

  my $port = find_listenable_port;
  my $host = Web::Host->parse_string ('127.0.0.1');

  my @done;

  my $destroyed = 0;
  my $server = tcp_server undef, $port, sub {
    create_tls_server ($_[0], $_[1], $_[2])->then (sub {
      my $info = $_[0];

      my $w = $info->{writable}->get_writer;
      my $r = $info->{readable}->get_reader ('byob');

      $info->{readable}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';
      $info->{writable}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';

      push @done, $r->closed;

      my $buffer = '';
      my $read; $read = sub {
        return $r->read (dv "x" x (1 + int rand 4))->then (sub {
          if ($_[0]->{done}) {
            $w->close if defined $w;
            return;
          }
          my $dv = $_[0]->{value};
          my $offset = $dv->byte_offset;
          my $length = $dv->byte_length;
          my $value = substr ${$dv->buffer->manakai_transfer_to_scalarref}, $offset, $length;
          $buffer .= $value;
          while ($buffer =~ s/^([^\x0A]*)\x0A//) {
            $w->write (dv (($1 - 1) . "\x0A")) if $1 > 0;
            ($w->close, undef $w) if $1 <= 0;
          }
          return $read->();
        });
      };
      return $read->()->then (sub { undef $read });
    });
  }; # $server

  create_tls_client ($host, $port)->then (sub {
    my $info = $_[0];
    my $w = $info->{writable}->get_writer;
    my $r = $info->{readable}->get_reader ('byob');

    $info->{readable}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';
    $info->{writable}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';

    push @done, $r->closed;

    my $start = 1 + int rand 100;
    $w->write (dv $start);
    Promise->resolve->then (sub {
      $w->write (dv "\x0A");
    });

    my @received;
    my $buffer = '';
    my $try; $try = sub {
      return $r->read (dv "x" x 10)->then (sub {
        my $v = $_[0];
        if ($v->{done}) {
          $w->close if defined $w;
          return;
        }

        my $dv = $_[0]->{value};
        my $offset = $dv->byte_offset;
        my $length = $dv->byte_length;
        my $value = substr ${$dv->buffer->manakai_transfer_to_scalarref}, $offset, $length;
        $buffer .= $value;
        while ($buffer =~ s/^([^\x0A]*)\x0A//) {
          push @received, $1;
          $w->write (dv (($1 - 1) . "\x0A")) if $1 > 0;
          ($w->close, undef $w) if $1 <= 0;
        }

        return $try->();
      });
    };

    return $try->()->then (sub {
      test {
        my $result = join " ", @received;
        my @expected;
        $start--;
        while ($start >= 0) {
          push @expected, $start;
          $start -= 2;
        }
        is $result, join ' ', @expected;
      } $c;
      undef $try;
    });
  })->catch (sub {
    my $e = $_[0];
    test {
      ok 0, $e;
    } $c;
  })->then (sub {
    return Promise->all (\@done);
  })->then (sub {
    return promised_wait_until { $destroyed == 4 } timeout => 3;
  })->then (sub {
    test {
      is $destroyed, 4;
    } $c;
    done $c;
    undef $c;
    undef $server;
  });
} n => 2, name => 'a line-oriented interactive server';

test {
  my $c = shift;
  ok $Web::DOM::Error::L1ObjectClass->{'Web::Transport::TLSStream::OpenSSLError'};
  done $c;
} n => 1, name => 'Perl Error Object Interface Level 1';

test {
  my $c = shift;

  my $port = find_listenable_port;
  my $host = Web::Host->parse_string ('127.0.0.1');

  my $destroyed;
  my $server = tcp_server undef, $port, sub {
    create_tls_server ($_[0], $_[1], $_[2])->then (sub {
      my $info = $_[0];

      my $w = $info->{writable}->get_writer;
      my $r = $info->{readable}->get_reader ('byob');

      $info->{readable}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';
      $info->{writable}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';

      my $read; $read = sub {
        return $r->read (dv "x" x 10)->then (sub {
          if ($_[0]->{done}) {
            $w->close;
            return;
          }
          $w->write ($_[0]->{value});
          return $read->();
        });
      };
      return $read->()->then (sub { undef $read }, sub { undef $read });
    });
  }; # $server

  create_tls_client ($host, $port)->then (sub {
    my $info = $_[0];
    my $w = $info->{writable}->get_writer;
    my $r = $info->{readable}->get_reader ('byob');

    $info->{readable}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';
    $info->{writable}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';

    $w->write (dv "abcdef");
    $w->write (dv "foo bar 123");
    my $q = $w->write ("abcde");

    my @result;
    my $try; $try = sub {
      return $r->read (dv "x" x 10)->then (sub {
        my $v = $_[0];
        return if $v->{done};
        push @result, $v->{value};
        return $try->();
      });
    };

    return $try->()->catch (sub {
      my $e = $_[0];
      test {
        is $e->name, 'TypeError', $e;
        is $e->message, 'The argument is not an ArrayBufferView';
        is $e->file_name, __FILE__;
        is $e->line_number, __LINE__-20;
      } $c;
      return $q->catch (sub {
        my $f = $_[0];
        test {
          is $f, $e, 'write rejection';
        } $c;
        undef $try;
      });
    });
  })->catch (sub {
    my $e = $_[0];
    test {
      ok 0, $e;
    } $c;
  })->then (sub {
    return promised_wait_until { $destroyed == 4 } timeout => 3;
  })->then (sub {
    test {
      is $destroyed, 4;
    } $c;
    done $c;
    undef $c;
    undef $server;
  });
} n => 6, name => 'bad write';

test {
  my $c = shift;

  my $port = find_listenable_port;
  my $host = Web::Host->parse_string ('127.0.0.1');

  my $destroyed;
  my $server = tcp_server undef, $port, sub {
    create_tls_server ($_[0], $_[1], $_[2])->then (sub {
      my $info = $_[0];

      my $w = $info->{writable}->get_writer;
      my $r = $info->{readable}->get_reader ('byob');

      $info->{readable}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';
      $info->{writable}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';

      my $read; $read = sub {
        return $r->read (dv "x" x 10)->then (sub {
          if ($_[0]->{done}) {
            $w->close;
            return;
          }
          $w->write ($_[0]->{value});
          return $read->();
        });
      };
      return $read->()->then (sub { undef $read }, sub { undef $read });
    });
  }; # $server

  create_tls_client ($host, $port)->then (sub {
    my $info = $_[0];
    my $w = $info->{writable}->get_writer;
    my $r = $info->{readable}->get_reader ('byob');

    $info->{readable}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';
    $info->{writable}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';

    $w->write (dv "abcdef");
    $w->write (dv "foo bar 123");
    my $dv = dv "abcd";
    my $q = $w->write ($dv);
    $dv->buffer->_transfer; # detach

    my @result;
    my $try; $try = sub {
      return $r->read (dv "x" x 10)->then (sub {
        my $v = $_[0];
        return if $v->{done};
        push @result, $v->{value};
        return $try->();
      });
    };

    return $try->()->catch (sub {
      my $e = $_[0];
      test {
        is $e->name, 'TypeError', $e;
        is $e->message, 'ArrayBuffer is detached';
        is $e->file_name, __FILE__;
        is $e->line_number, __LINE__-22;
      } $c;
      return $q->catch (sub {
        my $f = $_[0];
        test {
          is $f, $e, 'write rejection';
        } $c;
        undef $try;
      });
    });
  })->catch (sub {
    my $e = $_[0];
    test {
      ok 0, $e;
    } $c;
  })->then (sub {
    return promised_wait_until { $destroyed == 4 } timeout => 3;
  })->then (sub {
    test {
      is $destroyed, 4;
    } $c;
    done $c;
    undef $c;
    undef $server;
  });
} n => 6, name => 'bad write';

test {
  my $c = shift;

  my $port = find_listenable_port;
  my $host = Web::Host->parse_string ('127.0.0.1');

  my $destroyed = 0;
  my $server = tcp_server undef, $port, sub {
    create_tls_server ($_[0], $_[1], $_[2])->then (sub {
      my $info = $_[0];

      my $w = $info->{writable}->get_writer;
      my $r = $info->{readable}->get_reader ('byob');

      $info->{readable}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';
      $info->{writable}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';

      my $read; $read = sub {
        return $r->read (dv "x" x 10)->then (sub {
          if ($_[0]->{done}) {
            $w->close;
            return;
          }
          $w->write ($_[0]->{value});
          return $read->();
        });
      };
      return $read->()->then (sub { undef $read }, sub { undef $read });
    });
  }; # $server

  create_tls_client ($host, $port)->then (sub {
    my $info = $_[0];
    my $w = $info->{writable}->get_writer;
    my $r = $info->{readable}->get_reader ('byob');

    $info->{readable}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';
    $info->{writable}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';

    $w->write (dv "abcdef");
    $w->write (dv "foo bar 123");

    my $result = '';
    my $q;
    my $s;
    my $reason = {};
    my $try; $try = sub {
      my $p = $r->read (dv "x" x 10)->then (sub {
        my $v = $_[0];
        return if $v->{done};
        $result .= $v->{value}->manakai_to_string;
        return $try->();
      });
      if ($result =~ /^abcdeff/) {
        $s = $r->cancel ($reason);
      }
      return $p;
    }; # $try

    return ((promised_cleanup { undef $try } $try->())->then (sub {
      test {
        like $result, qr{^abcdeff};
      } $c;
      return Promise->all ([$q, $s]);
    })->then (sub {
      test {
        ok 1;
      } $c;
    }));
  })->catch (sub {
    my $e = $_[0];
    test {
      ok 0, $e;
    } $c;
  })->then (sub {
    return promised_wait_until { $destroyed == 4 } timeout => 3;
  })->then (sub {
    test {
      is $destroyed, 4;
    } $c;
    done $c;
    undef $c;
    undef $server;
  });
} n => 3, name => 'read cancel 1';

test {
  my $c = shift;

  my $port = find_listenable_port;
  my $host = Web::Host->parse_string ('127.0.0.1');

  my $destroyed = 0;
  my $server = tcp_server undef, $port, sub {
    create_tls_server ($_[0], $_[1], $_[2])->then (sub {
      my $info = $_[0];

      my $w = $info->{writable}->get_writer;
      my $r = $info->{readable}->get_reader ('byob');

      $info->{readable}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';
      $info->{writable}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';

      my $read; $read = sub {
        return $r->read (dv "x" x 10)->then (sub {
          if ($_[0]->{done}) {
            $w->close;
            return;
          }
          $w->write ($_[0]->{value});
          return $read->();
        });
      };
      return $read->()->then (sub { undef $read }, sub { undef $read });
    });
  }; # $server

  create_tls_client ($host, $port)->then (sub {
    my $info = $_[0];
    my $w = $info->{writable}->get_writer;
    my $r = $info->{readable}->get_reader ('byob');

    $info->{readable}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';
    $info->{writable}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';

    $w->write (dv "abcdef");
    $w->write (dv "foo bar 123");

    my $result = '';
    my $q;
    my $s;
    my $reason = {};
    my $try; $try = sub {
      my $p = $r->read (dv "x" x 10)->then (sub {
        my $v = $_[0];
        return if $v->{done};
        $result .= $v->{value}->manakai_to_string;
        return $try->();
      });
      if (not defined $q and $result =~ /^abcdeff/) {
        $q = $w->close;
        $s = $r->cancel ($reason);
      }
      return $p;
    }; # $try

    return ((promised_cleanup { undef $try } $try->())->then (sub {
      test {
        like $result, qr{^abcdeff};
      } $c;
      return $q;
    })->then (sub {
      test {
        ok 1, 'Writer close succeeded';
      } $c;
    }, sub {
      my $error = $_[0];
      test {
        is $error, $reason, 'Writer close failed because cancel is processed before close';
      } $c;
    })->then (sub {
      return $s;
    })->then (sub {
      test {
        ok 1;
      } $c;
    }));
  })->catch (sub {
    my $e = $_[0];
    test {
      ok 0, $e;
    } $c;
  })->then (sub {
    return promised_wait_until { $destroyed == 4 } timeout => 3;
  })->then (sub {
    test {
      is $destroyed, 4;
    } $c;
    done $c;
    undef $c;
    undef $server;
  });
} n => 4, name => 'read cancel 2';

test {
  my $c = shift;

  my $port = find_listenable_port;
  my $host = Web::Host->parse_string ('255.0.0.1');

  my $ac = new AbortController;
  promised_sleep (1)->then (sub {
    $ac->abort;
  });

  Web::Transport::TLSStream->create ({
    host => Web::Host->parse_string (Test::Certificates->cert_name),
    ca_file => Test::Certificates->ca_path ('cert.pem'),
    parent => {
      class => 'Web::Transport::TCPStream',
      host => $host,
      port => $port,
    },
    signal => $ac->signal,
  })->then (sub {
    test {
      ok 0;
    } $c;
  })->catch (sub {
    my $e = $_[0];
    test {
      ok $Web::DOM::Error::L1ObjectClass->{ref $e};
      is $e->name, 'AbortError';
      is $e->message, 'Aborted';
      is $e->file_name, __FILE__;
      is $e->line_number, __LINE__-23;
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 5, name => 'abort connect';

test {
  my $c = shift;

  my $port = find_listenable_port;
  my $host = Web::Host->parse_string ('127.0.0.1');

  my $invoked = 0;
  my $destroyed = 0;
  my $server = tcp_server undef, $port, sub {
    Web::Transport::TCPStream->create ({
      server => 1,
      fh => $_[0],
      host => Web::Host->parse_string ($_[1]),
      port => $_[2],
    })->then (sub {
      my $info = $_[0];
      $invoked++;
    });
  }; # $server

  my $ac = new AbortController;
  $ac->abort;

  Web::Transport::TLSStream->create ({
    host => Web::Host->parse_string (Test::Certificates->cert_name),
    ca_file => Test::Certificates->ca_path ('cert.pem'),
    parent => {
      class => 'Web::Transport::TCPStream',
      host => $host,
      port => $port,
    },
    signal => $ac->signal,
  })->then (sub {
    test {
      ok 0;
    } $c;
  })->catch (sub {
    my $e = $_[0];
    test {
      ok $Web::DOM::Error::L1ObjectClass->{ref $e};
      is $e->name, 'AbortError';
      is $e->message, 'Aborted';
      is $e->file_name, __FILE__;
      is $e->line_number, __LINE__-22;
      is $invoked, 0;
    } $c;
  })->then (sub {
    done $c;
    undef $c;
    undef $server;
  });
} n => 6, name => 'abort connect before connect';

test {
  my $c = shift;

  my $port = find_listenable_port;
  my $host = Web::Host->parse_string ('127.0.0.1');

  my $invoked = 0;
  my $server_info;
  my $server = tcp_server undef, $port, sub {
    Web::Transport::TCPStream->create ({
      server => 1,
      fh => $_[0],
      host => Web::Host->parse_string ($_[1]),
      port => $_[2],
    })->then (sub {
      my $info = $_[0];
      $server_info = $info;
      $invoked++;
    });
  }; # $server

  my $ac = new AbortController;

  my $real_host = Web::Host->parse_string ('10.44.13.111');
  my $real_port = 1 + int rand 10000;

  (promised_wait_until { $invoked } timeout => 30, interval => 0.1)->then (sub {
    $ac->abort;
  });

  Web::Transport::TLSStream->create ({
    host => Web::Host->parse_string (Test::Certificates->cert_name),
    ca_file => Test::Certificates->ca_path ('cert.pem'),
    parent => {
      class => 'Web::Transport::TCPStream',
      host => $host,
      port => $port,
    },
    signal => $ac->signal,
  })->then (sub {
    test {
      ok 0;
    } $c;
  })->catch (sub {
    my $e = $_[0];
    test {
      ok $Web::DOM::Error::L1ObjectClass->{ref $e};
      is $e->name, 'AbortError';
      is $e->message, 'Aborted';
      is $e->file_name, __FILE__;
      is $e->line_number, __LINE__-23;
    } $c;
  })->then (sub {
    done $c;
    undef $c;
    undef $server;
    $server_info->{writable}->abort;
  });
} n => 5, name => 'abort connect after tcp connected';

Test::Certificates->wait_create_cert;
run_tests;

=head1 LICENSE

Copyright 2017-2018 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
