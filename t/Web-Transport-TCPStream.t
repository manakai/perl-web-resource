use strict;use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->child ('js');
use lib glob path (__FILE__)->parent->parent->parent->child ('perl-streams/lib');

use lib glob path (__FILE__)->parent->parent->child ('t_deps/modules/*/lib');
use Test::More;
use Test::X1;
use TCPTransport;
use Web::Host;
use AnyEvent::Socket qw(tcp_server);
use DataView;
use ArrayBuffer;
use Promised::Flow;

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

test {
  my $c = shift;
  TCPTransport->create ({
    port => 3223,
  })->catch (sub {
    my $e = $_[0];
    test {
      isa_ok $e, 'Web::DOM::TypeError', $e;
      is $e->name, 'TypeError';
      is $e->message, 'Bad |host|';
      is $e->file_name, __FILE__;
      is $e->line_number, __LINE__+4;
    } $c;
    done $c;
    undef $c;
  });
} n => 5, name => 'create bad |host|';

test {
  my $c = shift;
  my $host = Web::Host->parse_string ("hoge.test");
  TCPTransport->create ({
    host => $host,
    port => 3223,
  })->catch (sub {
    my $e = $_[0];
    test {
      isa_ok $e, 'Web::DOM::TypeError', $e;
      is $e->name, 'TypeError';
      is $e->message, 'Bad |host|';
      is $e->file_name, __FILE__;
      is $e->line_number, __LINE__+4;
    } $c;
    done $c;
    undef $c;
  });
} n => 5, name => 'create bad |host|';

for my $value (
  undef, -1, -4242, 0+"inf", 0-"inf", 0+"nan", 42.44, 93.001,
  2**16, 2**32+13,
) {
  test {
    my $c = shift;
    my $host = Web::Host->parse_string ("127.0.0.33");
    TCPTransport->create ({
      host => $host,
      port => $value,
    })->catch (sub {
      my $e = $_[0];
      test {
        isa_ok $e, 'Web::DOM::TypeError', $e;
        is $e->name, 'TypeError';
        is $e->message, 'Bad |port|';
        is $e->file_name, __FILE__;
        is $e->line_number, __LINE__+4;
      } $c;
      done $c;
      undef $c;
    });
  } n => 5, name => 'create bad |port|';
}

test {
  my $c = shift;
  my $host = Web::Host->parse_string ('127.0.53.53');
  TCPTransport->create ({
    host => $host,
    port => 3223,
  })->catch (sub {
    my $e = $_[0];
    test {
      isa_ok $e, 'Web::DOM::TypeError', $e;
      is $e->name, 'TypeError';
      is $e->message, 'ICANN_NAME_COLLISION';
      is $e->file_name, __FILE__;
      is $e->line_number, __LINE__+4;
    } $c;
    done $c;
    undef $c;
  });
} n => 5, name => 'new IANA collision';

test {
  my $c = shift;
  my $host = Web::Host->parse_string ('127.0.0.44');
  TCPTransport->create ({
    host => $host,
    port => 322355,
  })->catch (sub {
    my $e = $_[0];
    test {
      ok $e->name;
      ok $e->message;
    } $c;
    done $c;
    undef $c;
  });
} n => 2, name => 'new connect error';

test {
  my $c = shift;
  TCPTransport->create ({server => 1})->catch (sub {
    my $e = $_[0];
    test {
      is $e->name, 'TypeError';
      is $e->message, 'Bad |fh|';
      is $e->file_name, __FILE__;
      is $e->line_number, __LINE__+4;
    } $c;
    done $c;
    undef $c;
  });
} n => 4, name => 'create with |server| but no |fh|';

test {
  my $c = shift;

  my $port = find_listenable_port;
  my $host = Web::Host->parse_string ('127.0.0.1');

  my $destroyed = 0;

  my $server = tcp_server undef, $port, sub {
    TCPTransport->create ({
      server => 1,
      fh => $_[0],
      host => Web::Host->parse_string ($_[1]),
      port => $_[2],
    })->then (sub {
      my $info = $_[0];

      my $w = $info->{write_stream}->get_writer;
      my $r = $info->{read_stream}->get_reader;

      $info->{read_stream}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';
      $info->{write_stream}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';

      $w->write (DataView->new (ArrayBuffer->new_from_scalarref (\"abce"), 3, 0));
      $w->write (dv "abc");
      $w->write (DataView->new (ArrayBuffer->new_from_scalarref (\"AAxyzTWW"), 2, 3));
      $w->close;

    });
  }; # $server

  TCPTransport->create ({
    host => $host,
    port => $port,
  })->then (sub {
    my $info = $_[0];
    my $w = $info->{write_stream}->get_writer;
    my $r = $info->{read_stream}->get_reader ('byob');
    my @result;

    $info->{read_stream}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';
    $info->{write_stream}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';

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
    TCPTransport->create ({
      server => 1,
      fh => $_[0],
      host => Web::Host->parse_string ($_[1]),
      port => $_[2],
    })->then (sub {
      my $info = $_[0];

      my $w = $info->{write_stream}->get_writer;
      my $r = $info->{read_stream}->get_reader;

      $info->{read_stream}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';
      $info->{write_stream}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';

      $w->write (dv "abc");
      $w->write (dv "xyz");
      $w->close;

    });
  }; # $server

  TCPTransport->create ({
    host => $host,
    port => $port,
  })->then (sub {
    my $info = $_[0];
    my $w = $info->{write_stream}->get_writer;
    my $r = $info->{read_stream}->get_reader ('byob');
    my @result;

    $info->{read_stream}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';
    $info->{write_stream}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';

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

  my $destroyed = 0;
  my $server = tcp_server undef, $port, sub {
    TCPTransport->create ({
      server => 1,
      fh => $_[0],
      host => Web::Host->parse_string ($_[1]),
      port => $_[2],
    })->then (sub {
      my $info = $_[0];

      my $w = $info->{write_stream}->get_writer;
      my $r = $info->{read_stream}->get_reader;

      $info->{read_stream}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';
      $info->{write_stream}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';

      $w->write (dv "abc");
      $w->write (dv "xyz");
      $w->close;

    });
  }; # $server

  TCPTransport->create ({
    host => $host,
    port => $port,
  })->then (sub {
    my $info = $_[0];
    my $w = $info->{write_stream}->get_writer;
    my $r = $info->{read_stream}->get_reader;

    $info->{read_stream}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';
    $info->{write_stream}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';

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

  my $destroyed = 0;
  my $server = tcp_server undef, $port, sub {
    TCPTransport->create ({
      server => 1,
      fh => $_[0],
      host => Web::Host->parse_string ($_[1]),
      port => $_[2],
    })->then (sub {
      my $info = $_[0];

      my $w = $info->{write_stream}->get_writer;
      my $r = $info->{read_stream}->get_reader ('byob');

      $info->{read_stream}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';
      $info->{write_stream}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';

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

  TCPTransport->create ({
    host => $host,
    port => $port,
  })->then (sub {
    my $info = $_[0];
    my $w = $info->{write_stream}->get_writer;
    my $r = $info->{read_stream}->get_reader ('byob');

    $info->{read_stream}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';
    $info->{write_stream}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';

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
    TCPTransport->create ({
      server => 1,
      fh => $_[0],
      host => Web::Host->parse_string ($_[1]),
      port => $_[2],
    })->then (sub {
      my $info = $_[0];

      my $w = $info->{write_stream}->get_writer;
      my $r = $info->{read_stream}->get_reader ('byob');

      $info->{read_stream}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';
      $info->{write_stream}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';

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

  TCPTransport->create ({
    host => $host,
    port => $port,
  })->then (sub {
    my $info = $_[0];
    my $w = $info->{write_stream}->get_writer;
    my $r = $info->{read_stream}->get_reader;

    $info->{read_stream}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';
    $info->{write_stream}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';

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
    TCPTransport->create ({
      server => 1,
      fh => $_[0],
      host => Web::Host->parse_string ($_[1]),
      port => $_[2],
    })->then (sub {
      my $info = $_[0];

      my $w = $info->{write_stream}->get_writer;
      my $r = $info->{read_stream}->get_reader ('byob');

      $info->{read_stream}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';
      $info->{write_stream}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';

      push @done, $r->closed;

      my $buffer = '';
      my $read; $read = sub {
        return $r->read (dv "x" x (1 + int rand 4))->then (sub {
          if ($_[0]->{done}) {
            $w->close if defined $w;
            return;
          }
          my $dv = $_[0]->{value};
          my $value = $dv->manakai_to_string;
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

  TCPTransport->create ({
    host => $host,
    port => $port,
  })->then (sub {
    my $info = $_[0];
    my $w = $info->{write_stream}->get_writer;
    my $r = $info->{read_stream}->get_reader ('byob');

    $info->{read_stream}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';
    $info->{write_stream}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';

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
        my $value = $dv->manakai_to_string;
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

  my $port = find_listenable_port;
  my $host = Web::Host->parse_string ('127.0.0.1');

  my $destroyed = 0;
  my $server = tcp_server undef, $port, sub {
    TCPTransport->create ({
      server => 1,
      fh => $_[0],
      host => Web::Host->parse_string ($_[1]),
      port => $_[2],
    })->then (sub {
      my $info = $_[0];

      my $w = $info->{write_stream}->get_writer;
      my $r = $info->{read_stream}->get_reader ('byob');

      $info->{read_stream}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';
      $info->{write_stream}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';

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
      return $read->()->catch (sub {
        #
      })->then (sub { undef $read });
    });
  }; # $server

  TCPTransport->create ({
    host => $host,
    port => $port,
  })->then (sub {
    my $info = $_[0];
    my $w = $info->{write_stream}->get_writer;
    my $r = $info->{read_stream}->get_reader ('byob');

    $info->{read_stream}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';
    $info->{write_stream}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';

    $w->write (dv "abcdef");
    $w->write (dv "foo bar 123")->then (sub {
      $w->abort;
    });

    return $w->closed->then (sub {
      test { ok 0 } $c;
    }, sub {
      test {
        ok 1;
      } $c;
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
} n => 2, name => 'abort 1';

test {
  my $c = shift;

  my $port = find_listenable_port;
  my $host = Web::Host->parse_string ('127.0.0.1');

  my $destroyed = 0;
  my $server = tcp_server undef, $port, sub {
    TCPTransport->create ({
      server => 1,
      fh => $_[0],
      host => Web::Host->parse_string ($_[1]),
      port => $_[2],
    })->then (sub {
      my $info = $_[0];

      my $w = $info->{write_stream}->get_writer;
      my $r = $info->{read_stream}->get_reader ('byob');

      $info->{read_stream}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';
      $info->{write_stream}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';

      my $read; $read = sub {
        return $r->read (dv "x" x 10)->then (sub {
          if ($_[0]->{done}) {
            $w->abort;
            return;
          }
          return $read->();
        });
      };
      return $read->()->then (sub { undef $read });
    });
  }; # $server

  TCPTransport->create ({
    host => $host,
    port => $port,
  })->then (sub {
    my $info = $_[0];
    my $w = $info->{write_stream}->get_writer;
    my $r = $info->{read_stream}->get_reader ('byob');

    $info->{read_stream}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';
    $info->{write_stream}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';

    $r->read (DataView->new (ArrayBuffer->new (1)));
    $w->write (dv "abcdef");
    $w->write (dv "foo bar 123")->then (sub {
      $w->abort;
    });

    return $w->closed->then (sub {
      test { ok 0 } $c;
    }, sub {
      test {
        ok 1;
      } $c;
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
} n => 2, name => 'abort 2';

test {
  my $c = shift;

  my $port = find_listenable_port;
  my $host = Web::Host->parse_string ('127.0.0.1');

  my $destroyed = 0;
  my $server = tcp_server undef, $port, sub {
    TCPTransport->create ({
      server => 1,
      fh => $_[0],
      host => Web::Host->parse_string ($_[1]),
      port => $_[2],
    })->then (sub {
      my $info = $_[0];

      my $w = $info->{write_stream}->get_writer;
      my $r = $info->{read_stream}->get_reader ('byob');

      $info->{read_stream}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';
      $info->{write_stream}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';

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

  TCPTransport->create ({
    host => $host,
    port => $port,
  })->then (sub {
    my $info = $_[0];
    my $w = $info->{write_stream}->get_writer;
    my $r = $info->{read_stream}->get_reader ('byob');

    $info->{read_stream}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';
    $info->{write_stream}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';

    $w->write (dv "abcdef");
    $w->write (dv "foo bar 123");

    my $result = '';
    my $try; $try = sub {
      return $r->read (dv "x" x 10)->then (sub {
        my $v = $_[0];
        return if $v->{done};
        $result .= $v->{value}->manakai_to_string;
        if ($result =~ /^abcdeff/) {
          $w->abort (TCPTransport::Reset->new);
        }
        return $try->();
      });
    };

    return $try->()->catch (sub {
      my $e = $_[0];
      test {
        like $result, qr{^abcdeff};
        isa_ok $e, 'TCPTransport::Reset';
        is $e->name, 'AbortError';
        ok $e->message;
        is $e->file_name, __FILE__;
        is $e->line_number, __LINE__-15;
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
} n => 7, name => 'reset 1';

test {
  my $c = shift;

  my $port = find_listenable_port;
  my $host = Web::Host->parse_string ('127.0.0.1');

  my $destroyed = 0;
  my $got = '';
  my $server = tcp_server undef, $port, sub {
    TCPTransport->create ({
      server => 1,
      fh => $_[0],
      host => Web::Host->parse_string ($_[1]),
      port => $_[2],
    })->then (sub {
      my $info = $_[0];

      my $w = $info->{write_stream}->get_writer;
      my $r = $info->{read_stream}->get_reader ('byob');

      $info->{read_stream}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';
      $info->{write_stream}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';

      my $read; $read = sub {
        return $r->read (dv "x" x 10)->then (sub {
          $got .= $_[0]->{value}->manakai_to_string;
          $w->write ($_[0]->{value});
          if ($got =~ /^abcdeff/) {
            $w->abort (TCPTransport::Reset->new);
          }
          return $read->();
        });
      };
      return $read->()->then (sub { undef $read }, sub { undef $read });
    });
  }; # $server

  TCPTransport->create ({
    host => $host,
    port => $port,
  })->then (sub {
    my $info = $_[0];
    my $w = $info->{write_stream}->get_writer;
    my $r = $info->{read_stream}->get_reader ('byob');

    $info->{read_stream}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';
    $info->{write_stream}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';

    $w->write (dv "abcdef");
    $w->write (dv "foo bar 123");

    my $result = '';
    my $try; $try = sub {
      return $r->read (dv "x" x 10)->then (sub {
        my $v = $_[0];
        return if $v->{done};
        $result .= $v->{value}->manakai_to_string;
        return $try->();
      });
    };

    return $try->()->catch (sub {
      my $e = $_[0];
      test {
        like $got, qr{^abcdeff};
        is $e->name, 'Perl I/O error';
        ok $e->message;
        #is $e->file_name, __FILE__;
        #is $e->line_number, __LINE__-15;
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
} n => 4, name => 'reset 2';

test {
  my $c = shift;
  ok $Web::DOM::Error::L1ObjectClass->{'TCPTransport::Reset'};
  done $c;
} n => 1, name => 'Perl Error Object Interface Level 1';

test {
  my $c = shift;

  my $port = find_listenable_port;
  my $host = Web::Host->parse_string ('127.0.0.1');

  my $destroyed = 0;
  my $server = tcp_server undef, $port, sub {
    TCPTransport->create ({
      server => 1,
      fh => $_[0],
      host => Web::Host->parse_string ($_[1]),
      port => $_[2],
    })->then (sub {
      my $info = $_[0];

      my $w = $info->{write_stream}->get_writer;
      my $r = $info->{read_stream}->get_reader ('byob');

      $info->{read_stream}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';
      $info->{write_stream}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';

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

  TCPTransport->create ({
    host => $host,
    port => $port,
  })->then (sub {
    my $info = $_[0];
    my $w = $info->{write_stream}->get_writer;
    my $r = $info->{read_stream}->get_reader ('byob');

    $info->{read_stream}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';
    $info->{write_stream}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';

    $w->write (dv "abcdef");
    $w->write (dv "foo bar 123");

    my $result = '';
    my $q;
    my $try; $try = sub {
      return $r->read (dv "x" x 10)->then (sub {
        my $v = $_[0];
        return if $v->{done};
        $result .= $v->{value}->manakai_to_string;
        if ($result =~ /^abcdeff/) {
          $q = $w->write ("abcde");
        }
        return $try->();
      });
    };

    return $try->()->catch (sub {
      my $e = $_[0];
      test {
        like $result, qr{^abcdeff};
        is $e->name, 'TypeError', $e;
        is $e->message, 'The argument is not an ArrayBufferView';
        #is $e->file_name, __FILE__;
        #is $e->line_number, __LINE__-15;
      } $c;
      return $q->catch (sub {
        my $f = $_[0];
        test {
          is $f, $e, "write rejection";
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
} n => 5, name => 'bad write';

run_tests;
