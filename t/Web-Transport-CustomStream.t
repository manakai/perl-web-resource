use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->child ('t_deps/modules/*/lib');
use Test::More;
use Test::X1;
use Web::Host;
use AnyEvent::Socket qw(tcp_server);
use DataView;
use ArrayBuffer;
use Promised::Flow;
use Web::Transport::TCPStream;
use Web::Transport::CustomStream;

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

sub cs ($) {
  my $info = $_[0];
  return Web::Transport::CustomStream->create ({
    readable => $info->{readable},
    writable => $info->{writable},
    closed => $info->{closed},
  });
} # cs

test {
  my $c = shift;

  my $port = find_listenable_port;
  my $host = Web::Host->parse_string ('127.0.0.1');

  my $destroyed = 0;

  my $server = tcp_server undef, $port, sub {
    Web::Transport::TCPStream->create ({
      server => 1,
      fh => $_[0],
      host => Web::Host->parse_string ($_[1]),
      port => $_[2],
    })->then (sub {
      my $info = $_[0];
      return cs ($info);
    })->then (sub {
      my $info = $_[0];

      my $w = $info->{writable}->get_writer;
      my $r = $info->{readable}->get_reader;

      $info->{readable}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';
      $info->{writable}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';

      $w->write (DataView->new (ArrayBuffer->new_from_scalarref (\"abce"), 3, 0));
      $w->write (dv "abc");
      $w->write (DataView->new (ArrayBuffer->new_from_scalarref (\"AAxyzTWW"), 2, 3));
      $w->close;

    });
  }; # $server

  Web::Transport::TCPStream->create ({
    host => $host,
    port => $port,
  })->then (sub {
    my $info = $_[0];
    return cs ($info);
  })->then (sub {
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
    Web::Transport::TCPStream->create ({
      server => 1,
      fh => $_[0],
      host => Web::Host->parse_string ($_[1]),
      port => $_[2],
    })->then (sub {
      my $info = $_[0];
      return cs ($info);
    })->then (sub {
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

  Web::Transport::TCPStream->create ({
    host => $host,
    port => $port,
  })->then (sub {
    my $info = $_[0];
    return cs ($info);
  })->then (sub {
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
    Web::Transport::TCPStream->create ({
      server => 1,
      fh => $_[0],
      host => Web::Host->parse_string ($_[1]),
      port => $_[2],
    })->then (sub {
      my $info = $_[0];
      return cs ($info);
    })->then (sub {
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

  Web::Transport::TCPStream->create ({
    host => $host,
    port => $port,
  })->then (sub {
    my $info = $_[0];
    return cs ($info);
  })->then (sub {
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
    return promised_wait_until { $destroyed == 4 and @s >= 3 and @c >= 3 } timeout => 5;
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
} n => 10, name => 'a server returning constant data byob 2';

test {
  my $c = shift;

  my $port = find_listenable_port;
  my $host = Web::Host->parse_string ('127.0.0.1');

  my $destroyed = 0;
  my $server = tcp_server undef, $port, sub {
    Web::Transport::TCPStream->create ({
      server => 1,
      fh => $_[0],
      host => Web::Host->parse_string ($_[1]),
      port => $_[2],
    })->then (sub {
      my $info = $_[0];
      return cs ($info);
    })->then (sub {
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

  Web::Transport::TCPStream->create ({
    host => $host,
    port => $port,
  })->then (sub {
    my $info = $_[0];
    return cs ($info);
  })->then (sub {
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

  my $destroyed = 0;
  my $server = tcp_server undef, $port, sub {
    Web::Transport::TCPStream->create ({
      server => 1,
      fh => $_[0],
      host => Web::Host->parse_string ($_[1]),
      port => $_[2],
    })->then (sub {
      my $info = $_[0];
      return cs ($info);
    })->then (sub {
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

  Web::Transport::TCPStream->create ({
    host => $host,
    port => $port,
  })->then (sub {
    my $info = $_[0];
    return cs ($info);
  })->then (sub {
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
    Web::Transport::TCPStream->create ({
      server => 1,
      fh => $_[0],
      host => Web::Host->parse_string ($_[1]),
      port => $_[2],
    })->then (sub {
      my $info = $_[0];
      return cs ($info);
    })->then (sub {
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

  Web::Transport::TCPStream->create ({
    host => $host,
    port => $port,
  })->then (sub {
    my $info = $_[0];
    return cs ($info);
  })->then (sub {
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
    Web::Transport::TCPStream->create ({
      server => 1,
      fh => $_[0],
      host => Web::Host->parse_string ($_[1]),
      port => $_[2],
    })->then (sub {
      my $info = $_[0];
      return cs ($info);
    })->then (sub {
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

  Web::Transport::TCPStream->create ({
    host => $host,
    port => $port,
  })->then (sub {
    my $info = $_[0];
    return cs ($info);
  })->then (sub {
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
    Web::Transport::TCPStream->create ({
      server => 1,
      fh => $_[0],
      host => Web::Host->parse_string ($_[1]),
      port => $_[2],
    })->then (sub {
      my $info = $_[0];
      return cs ($info);
    })->then (sub {
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
      return $read->()->catch (sub {
        #
      })->then (sub { undef $read });
    });
  }; # $server

  Web::Transport::TCPStream->create ({
    host => $host,
    port => $port,
  })->then (sub {
    my $info = $_[0];
    return cs ($info);
  })->then (sub {
    my $info = $_[0];
    my $w = $info->{writable}->get_writer;
    my $r = $info->{readable}->get_reader ('byob');

    $info->{readable}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';
    $info->{writable}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';

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
    Web::Transport::TCPStream->create ({
      server => 1,
      fh => $_[0],
      host => Web::Host->parse_string ($_[1]),
      port => $_[2],
    })->then (sub {
      my $info = $_[0];
      return cs ($info);
    })->then (sub {
      my $info = $_[0];

      my $w = $info->{writable}->get_writer;
      my $r = $info->{readable}->get_reader ('byob');

      $info->{readable}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';
      $info->{writable}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';

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

  Web::Transport::TCPStream->create ({
    host => $host,
    port => $port,
  })->then (sub {
    my $info = $_[0];
    return cs ($info);
  })->then (sub {
    my $info = $_[0];
    my $w = $info->{writable}->get_writer;
    my $r = $info->{readable}->get_reader ('byob');

    $info->{readable}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';
    $info->{writable}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';

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
    Web::Transport::TCPStream->create ({
      server => 1,
      fh => $_[0],
      host => Web::Host->parse_string ($_[1]),
      port => $_[2],
    })->then (sub {
      my $info = $_[0];
      return cs ($info);
    })->then (sub {
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

  Web::Transport::TCPStream->create ({
    host => $host,
    port => $port,
  })->then (sub {
    my $info = $_[0];
    return cs ($info);
  })->then (sub {
    my $info = $_[0];
    my $w = $info->{writable}->get_writer;
    my $r = $info->{readable}->get_reader ('byob');

    $info->{readable}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';
    $info->{writable}->{_destroy} = bless sub { $destroyed++ }, 'test::DestroyCallback1';

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
        is $e->file_name, __FILE__;
        like $e->line_number, qr{(?:@{[join '|', __LINE__-14, __LINE__-13]})};
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
} n => 7, name => 'bad write';

test {
  my $c = shift;

  my $port = find_listenable_port;
  my $host = Web::Host->parse_string ('127.0.0.1');

  my $destroyed = 0;
  my $server = tcp_server undef, $port, sub {
    Web::Transport::TCPStream->create ({
      server => 1,
      fh => $_[0],
      host => Web::Host->parse_string ($_[1]),
      port => $_[2],
    })->then (sub {
      my $info = $_[0];
      return cs ($info);
    })->then (sub {
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

  Web::Transport::TCPStream->create ({
    host => $host,
    port => $port,
  })->then (sub {
    my $info = $_[0];
    return cs ($info);
  })->then (sub {
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
} n => 4, name => 'read cancel';

test {
  my $c = shift;
  Web::Transport::CustomStream->create ({})->catch (sub {
    my $e = $_[0];
    test {
      is $e->name, 'TypeError';
      is $e->message, 'Bad |readable|';
      is $e->file_name, __FILE__;
      is $e->line_number, __LINE__+4;
    } $c;
    done $c;
    undef $c;
  });
} n => 4, name => 'create error: no arguments';

test {
  my $c = shift;
  Web::Transport::CustomStream->create ({
    readable => ReadableStream->new,
  })->catch (sub {
    my $e = $_[0];
    test {
      is $e->name, 'TypeError';
      is $e->message, 'Bad |writable|';
      is $e->file_name, __FILE__;
      is $e->line_number, __LINE__+4;
    } $c;
    done $c;
    undef $c;
  });
} n => 4, name => 'create error: no writable';

test {
  my $c = shift;
  Web::Transport::CustomStream->create ({
    readable => ReadableStream->new,
    writable => WritableStream->new,
  })->catch (sub {
    my $e = $_[0];
    test {
      is $e->name, 'TypeError';
      is $e->message, 'Bad |closed|';
      is $e->file_name, __FILE__;
      is $e->line_number, __LINE__+4;
    } $c;
    done $c;
    undef $c;
  });
} n => 4, name => 'create error: no closed';

test {
  my $c = shift;
  my $in = {
    readable => ReadableStream->new,
    writable => WritableStream->new,
    closed => Promise->resolve,
  };
  Web::Transport::CustomStream->create ($in)->then (sub {
    my $info = $_[0];
    test {
      is $info->{readable}, $in->{readable};
      is $info->{writable}, $in->{writable};
      is $info->{closed}, $in->{closed};
      ok $info->{id};
      is $info->{type}, 'Custom';
      is $info->{layered_type}, 'Custom';
    } $c;
    done $c;
    undef $c;
  });
} n => 6, name => 'default props';

test {
  my $c = shift;
  my $in = {
    readable => ReadableStream->new,
    writable => WritableStream->new,
    closed => Promise->resolve,
    id => rand,
  };
  Web::Transport::CustomStream->create ($in)->then (sub {
    my $info = $_[0];
    test {
      is $info->{readable}, $in->{readable};
      is $info->{writable}, $in->{writable};
      is $info->{closed}, $in->{closed};
      is $info->{id}, $in->{id};
      is $info->{type}, 'Custom';
      is $info->{layered_type}, 'Custom';
    } $c;
    done $c;
    undef $c;
  });
} n => 6, name => 'props: id';

test {
  my $c = shift;
  my $in = {
    readable => ReadableStream->new,
    writable => WritableStream->new,
    closed => Promise->resolve,
    parent_id => rand,
  };
  Web::Transport::CustomStream->create ($in)->then (sub {
    my $info = $_[0];
    test {
      is $info->{readable}, $in->{readable};
      is $info->{writable}, $in->{writable};
      is $info->{closed}, $in->{closed};
      like $info->{id}, qr{^\Q$in->{parent_id}.\E.+};
      is $info->{type}, 'Custom';
      is $info->{layered_type}, 'Custom';
    } $c;
    done $c;
    undef $c;
  });
} n => 6, name => 'props: parent_id';

test {
  my $c = shift;
  my $in = {
    readable => ReadableStream->new,
    writable => WritableStream->new,
    closed => Promise->resolve,
    type => rand,
  };
  Web::Transport::CustomStream->create ($in)->then (sub {
    my $info = $_[0];
    test {
      is $info->{readable}, $in->{readable};
      is $info->{writable}, $in->{writable};
      is $info->{closed}, $in->{closed};
      ok $info->{id};
      is $info->{type}, $in->{type};
      is $info->{layered_type}, $in->{type};
    } $c;
    done $c;
    undef $c;
  });
} n => 6, name => 'props: type';

test {
  my $c = shift;
  my $in = {
    readable => ReadableStream->new,
    writable => WritableStream->new,
    closed => Promise->resolve,
    parent_layered_type => rand,
  };
  Web::Transport::CustomStream->create ($in)->then (sub {
    my $info = $_[0];
    test {
      is $info->{readable}, $in->{readable};
      is $info->{writable}, $in->{writable};
      is $info->{closed}, $in->{closed};
      ok $info->{id};
      is $info->{type}, 'Custom';
      is $info->{layered_type}, 'Custom/'.$in->{parent_layered_type};
    } $c;
    done $c;
    undef $c;
  });
} n => 6, name => 'props: parent_layered_type';

test {
  my $c = shift;
  my $in = {
    readable => ReadableStream->new,
    writable => WritableStream->new,
    closed => Promise->resolve,
    type => rand,
    parent_layered_type => rand,
  };
  Web::Transport::CustomStream->create ($in)->then (sub {
    my $info = $_[0];
    test {
      is $info->{readable}, $in->{readable};
      is $info->{writable}, $in->{writable};
      is $info->{closed}, $in->{closed};
      ok $info->{id};
      is $info->{type}, $in->{type};
      is $info->{layered_type}, $in->{type}.'/'.$in->{parent_layered_type};
    } $c;
    done $c;
    undef $c;
  });
} n => 6, name => 'props: parent_layered_type, type';

run_tests;

=head1 LICENSE

Copyright 2017-2018 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
