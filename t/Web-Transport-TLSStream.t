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
use Web::Transport::PKI::Generator;
use Web::Transport::DefaultCertificateManager;
use AbortController;
use Web::Transport::FindPort;

sub dv ($) {
  return DataView->new (ArrayBuffer->new_from_scalarref (\($_[0])));
} # dv

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
    undef $server;
  })->then (sub {
    done $c;
    undef $c;
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

test {
  my $c = shift;

  socket my $sock, Socket::PF_INET, Socket::SOCK_STREAM, 0;
  Web::Transport::TLSStream->create ({
    host => Web::Host->parse_string (Test::Certificates->cert_name),
    ca_file => Test::Certificates->ca_path ('cert.pem'),
    server => 1,
    parent => {
      class => 'Web::Transport::TCPStream',
      server => 1,
      fh => $sock,
      host => Web::Host->parse_string ("127.0.0.1"), port => 123,
    },
  })->catch (sub {
    my $e = $_[0];
    test {
      is $e->name, 'TypeError';
      is $e->message, 'Bad |cert|';
      is $e->file_name, __FILE__;
      is $e->line_number, __LINE__+4;
    } $c;
    done $c;
    undef $c;
  });
} n => 4, name => 'Bad |cert|';

test {
  my $c = shift;

  socket my $sock, Socket::PF_INET, Socket::SOCK_STREAM, 0;
  Web::Transport::TLSStream->create ({
    host => Web::Host->parse_string (Test::Certificates->cert_name),
    ca_file => Test::Certificates->ca_path ('cert.pem'),
    server => 1,
    cert => 'abc',
    parent => {
      class => 'Web::Transport::TCPStream',
      server => 1,
      fh => $sock,
      host => Web::Host->parse_string ("127.0.0.1"), port => 123,
    },
  })->catch (sub {
    my $e = $_[0];
    test {
      is $e->name, 'TypeError';
      is $e->message, 'Bad |key|';
      is $e->file_name, __FILE__;
      is $e->line_number, __LINE__+4;
    } $c;
    done $c;
    undef $c;
  });
} n => 4, name => 'Bad |key|';

test {
  my $c = shift;

  my $port = find_listenable_port;
  my $host = Web::Host->parse_string ('127.0.0.1');

  my $gen = Web::Transport::PKI::Generator->new;
  return $gen->create_rsa_key->then (sub {
    my $ca_rsa = $_[0];
    return $gen->create_certificate (
      rsa => $ca_rsa,
      ca_rsa => $ca_rsa,
      subject => {O => 'The Root CA'},
      issuer => {O => 'The Root CA'},
      not_before => time - 60,
      not_after => time + 3600,
      serial_number => 1,
      ca => 1,
    )->then (sub {
      my $ca_cert = $_[0];
      return $gen->create_rsa_key->then (sub {
        my $rsa = $_[0];
        return $gen->create_certificate (
          rsa => $rsa,
          ca_rsa => $ca_rsa,
          ca_cert => $ca_cert,
          not_before => time - 30,
          not_after => time + 3000,
          serial_number => 2,
          subject => {CN => 'server.test'},
          san_hosts => [$host],
          ee => 1,
        )->then (sub {
          my $cert = $_[0];
          return [$ca_cert, $ca_rsa, $cert, $rsa];
        });
      });
    });
  })->then (sub {
    my ($ca_cert, $ca_rsa, $cert, $rsa) = @{$_[0]};

    my $server = tcp_server undef, $port, sub {
      Web::Transport::TLSStream->create ({
        server => 1,
          ca_cert => $ca_cert->to_pem,
          cert => $cert->to_pem,
          key => $rsa->to_pem,
          parent => {
            class => 'Web::Transport::TCPStream',
            server => 1,
            fh => $_[0],
            host => Web::Host->parse_string ($_[1]),
            port => $_[2],
          },
        })->then (sub {
          my $info = $_[0];

          my $w = $info->{writable}->get_writer;
          my $r = $info->{readable}->get_reader ('byob');
          return promised_until {
            return $r->read (dv "x" x 10)->then (sub {
              my $v = $_[0];
              if ($v->{done}) {
                $w->close;
                return $info->{closed}->then (sub { return 1 });
              } else {
                $w->write ($v->{value});
                return 0;
              }
            });
          };
        });
    }; # $server

    my @result;
    return Web::Transport::TLSStream->create ({
      host => $host,
      ca_cert => $ca_cert->to_pem,
      parent => {
        class => 'Web::Transport::TCPStream',
        host => $host,
        port => $port,
      },
    })->then (sub {
      my $info = $_[0];
      my $w = $info->{writable}->get_writer;
      my $r = $info->{readable}->get_reader ('byob');

      $w->write (dv "abcdef");
      $w->write (dv "foo bar 123");
      $w->close;

      return promised_until {
        return $r->read (dv "x" x 10)->then (sub {
          my $v = $_[0];
          if ($v->{done}) {
            return $info->{closed}->then (sub { return 1 });
          } else {
            push @result, $v->{value};
            return 0;
          }
        });
      };
    })->then (sub {
      my $result = join '', map {
        $_->manakai_to_string;
      } @result;
      test {
        is $result, "abcdeffoo bar 123";
      } $c;
      undef $server;
    });
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 1, name => 'compat cert options';

test {
  my $c = shift;

  my $port = find_listenable_port;
  my $host = Web::Host->parse_string ('127.0.0.1');

  my $gen = Web::Transport::PKI::Generator->new;
  return Promise->all ([
    $gen->create_rsa_key,
    $gen->create_rsa_key,
  ])->then (sub {
    my $ca_rsa = $_[0]->[0];
    my $ca_rsa2 = $_[0]->[1];
    return Promise->all ([
      $gen->create_certificate (
        rsa => $ca_rsa,
        ca_rsa => $ca_rsa,
        subject => {O => 'The Root CA'},
        issuer => {O => 'The Root CA'},
        not_before => time - 60,
        not_after => time + 3600,
        serial_number => 1,
        ca => 1,
      ),
      $gen->create_certificate (
        rsa => $ca_rsa2,
        ca_rsa => $ca_rsa2,
        subject => {O => 'The Root CA'},
        issuer => {O => 'The Root CA'},
        not_before => time - 60,
        not_after => time + 3600,
        serial_number => 1,
        ca => 1,
      ),
    ])->then (sub {
      my $ca_cert = $_[0]->[0];
      my $ca_cert2 = $_[0]->[1];
      return $gen->create_rsa_key->then (sub {
        my $rsa = $_[0];
        return $gen->create_certificate (
          rsa => $rsa,
          ca_rsa => $ca_rsa,
          ca_cert => $ca_cert,
          not_before => time - 30,
          not_after => time + 3000,
          serial_number => 2,
          subject => {CN => 'server.test'},
          san_hosts => [$host],
          ee => 1,
        )->then (sub {
          my $cert = $_[0];

          #warn "CA: ", $ca_cert->debug_info;
          #warn "ee: ", $cert->debug_info;
          #warn "CA2: ", $ca_cert2->debug_info;

          return [$ca_cert, $ca_rsa, $cert, $rsa, $ca_cert2];
        });
      });
    });
  })->then (sub {
    my ($ca_cert, $ca_rsa, $cert, $rsa, $ca_cert2) = @{$_[0]};

    my @p;
    my $server = tcp_server undef, $port, sub {
      push @p, Web::Transport::TLSStream->create ({
        server => 1,
        ca_cert => $ca_cert->to_pem,
        cert => $cert->to_pem,
        key => $rsa->to_pem,
        parent => {
          class => 'Web::Transport::TCPStream',
          server => 1,
          fh => $_[0],
          host => Web::Host->parse_string ($_[1]),
          port => $_[2],
        },
      })->then (sub {
        my $info = $_[0];

        my $w = $info->{writable}->get_writer;
        my $r = $info->{readable}->get_reader ('byob');
        return promised_until {
          return $r->read (dv "x" x 10)->then (sub {
            my $v = $_[0];
            if ($v->{done}) {
              $w->close;
              return $info->{closed}->then (sub { return 1 });
            } else {
              $w->write ($v->{value});
              return 0;
            }
          });
        };
      })->catch (sub { });
    }; # $server

    my @result;
    return Web::Transport::TLSStream->create ({
      host => $host,
      ca_cert => $ca_cert2->to_pem,
      parent => {
        class => 'Web::Transport::TCPStream',
        host => $host,
        port => $port,
      },
    })->then (sub { test { ok 0 } $c }, sub {
      my $e = $_[0];
      test {
        isa_ok $e, 'Web::Transport::ProtocolError';
        is $e->name, 'Protocol error';
        my $m = $e->message;
        $m =~ s/self-signed/self signed/;
        #is $m, 'Certificate verification error 19 - self signed certificate in certificate chain'; # other error might be emitted depending on OpenSSL version
        like $m, qr{Certificate verification error};
        is $e->file_name, __FILE__;
        is $e->line_number, __LINE__+4;
      } $c;
      undef $server;
      return Promise->all (\@p);
    });
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 5, name => 'compat cert options, wrong client ca_cert';

test {
  my $c = shift;

  my $port = find_listenable_port;
  my $host = Web::Host->parse_string ('127.0.0.1');

  my $gen = Web::Transport::PKI::Generator->new;
  return $gen->create_rsa_key->then (sub {
    my $ca_rsa = $_[0];
    return $gen->create_certificate (
      rsa => $ca_rsa,
      ca_rsa => $ca_rsa,
      subject => {O => 'The Root CA'},
      issuer => {O => 'The Root CA'},
      not_before => time - 60,
      not_after => time + 3600,
      serial_number => 1,
      ca => 1,
    )->then (sub {
      my $ca_cert = $_[0];
      return $gen->create_rsa_key->then (sub {
        my $rsa = $_[0];
        return $gen->create_certificate (
          rsa => $rsa,
          ca_rsa => $ca_rsa,
          ca_cert => $ca_cert,
          not_before => time - 30,
          not_after => time + 3000,
          serial_number => 2,
          subject => {CN => 'server.test'},
          san_hosts => [$host],
          ee => 1,
        )->then (sub {
          my $cert = $_[0];
          return [$ca_cert, $ca_rsa, $cert, $rsa];
        });
      });
    });
  })->then (sub {
    my ($ca_cert, $ca_rsa, $cert, $rsa) = @{$_[0]};

    my $server = tcp_server undef, $port, sub {
      Web::Transport::TLSStream->create ({
        server => 1,
        ca_cert => $ca_cert,
        cert => $cert,
        key => $rsa,
        parent => {
          class => 'Web::Transport::TCPStream',
          server => 1,
          fh => $_[0],
          host => Web::Host->parse_string ($_[1]),
          port => $_[2],
        },
      })->then (sub {
        my $info = $_[0];

        my $w = $info->{writable}->get_writer;
        my $r = $info->{readable}->get_reader ('byob');
        return promised_until {
          return $r->read (dv "x" x 10)->then (sub {
            my $v = $_[0];
            if ($v->{done}) {
              $w->close;
              return $info->{closed}->then (sub { return 1 });
            } else {
              $w->write ($v->{value});
              return 0;
            }
          });
        };
      });
    }; # $server

    my @result;
    return Web::Transport::TLSStream->create ({
      host => $host,
      ca_cert => $ca_cert,
      parent => {
        class => 'Web::Transport::TCPStream',
        host => $host,
        port => $port,
      },
    })->then (sub {
      my $info = $_[0];
      my $w = $info->{writable}->get_writer;
      my $r = $info->{readable}->get_reader ('byob');

      $w->write (dv "abcdef");
      $w->write (dv "foo bar 123");
      $w->close;

      return promised_until {
        return $r->read (dv "x" x 10)->then (sub {
          my $v = $_[0];
          if ($v->{done}) {
            return $info->{closed}->then (sub { return 1 });
          } else {
            push @result, $v->{value};
            return 0;
          }
        });
      };
    })->then (sub {
      my $result = join '', map {
        $_->manakai_to_string;
      } @result;
      test {
        is $result, "abcdeffoo bar 123";
      } $c;
      undef $server;
    });
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 1, name => 'compat cert options, as objects';

test {
  my $c = shift;

  my $port = find_listenable_port;
  my $host = Web::Host->parse_string ('127.0.0.1');

  my $gen = Web::Transport::PKI::Generator->new;
  return $gen->create_rsa_key->then (sub {
    my $ca_rsa = $_[0];
    return $gen->create_certificate (
      rsa => $ca_rsa,
      ca_rsa => $ca_rsa,
      subject => {O => 'The Root CA'},
      issuer => {O => 'The Root CA'},
      not_before => time - 60,
      not_after => time + 3600,
      serial_number => 1,
      ca => 1,
    )->then (sub {
      my $ca_cert = $_[0];
      return $gen->create_rsa_key->then (sub {
        my $rsa = $_[0];
        return $gen->create_certificate (
          rsa => $rsa,
          ca_rsa => $ca_rsa,
          ca_cert => $ca_cert,
          not_before => time - 30,
          not_after => time + 3000,
          serial_number => 2,
          subject => {CN => 'server.test'},
          san_hosts => [$host],
          ee => 1,
        )->then (sub {
          my $cert = $_[0];
          return [$ca_cert, $ca_rsa, $cert, $rsa];
        });
      });
    });
  })->then (sub {
    my ($ca_cert, $ca_rsa, $cert, $rsa) = @{$_[0]};

    my $cm1 = Web::Transport::DefaultCertificateManager->new ({
      ca_cert => $ca_cert,
      cert => $cert,
      key => $rsa,
    });

    my $server = tcp_server undef, $port, sub {
      Web::Transport::TLSStream->create ({
        server => 1,
        certificate_manager => $cm1,
        parent => {
          class => 'Web::Transport::TCPStream',
          server => 1,
          fh => $_[0],
          host => Web::Host->parse_string ($_[1]),
          port => $_[2],
        },
      })->then (sub {
        my $info = $_[0];

        my $w = $info->{writable}->get_writer;
        my $r = $info->{readable}->get_reader ('byob');
        return promised_until {
          return $r->read (dv "x" x 10)->then (sub {
            my $v = $_[0];
            if ($v->{done}) {
              $w->close;
              return $info->{closed}->then (sub { return 1 });
            } else {
              $w->write ($v->{value});
              return 0;
            }
          });
        };
      });
    }; # $server

    my $cm2 = Web::Transport::DefaultCertificateManager->new ({
      ca_cert => $ca_cert,
    });

    my @result;
    return Web::Transport::TLSStream->create ({
      host => $host,
      certificate_manager => $cm2,
      parent => {
        class => 'Web::Transport::TCPStream',
        host => $host,
        port => $port,
      },
    })->then (sub {
      my $info = $_[0];
      my $w = $info->{writable}->get_writer;
      my $r = $info->{readable}->get_reader ('byob');

      $w->write (dv "abcdef");
      $w->write (dv "foo bar 123");
      $w->close;

      return promised_until {
        return $r->read (dv "x" x 10)->then (sub {
          my $v = $_[0];
          if ($v->{done}) {
            return $info->{closed}->then (sub { return 1 });
          } else {
            push @result, $v->{value};
            return 0;
          }
        });
      };
    })->then (sub {
      my $result = join '', map {
        $_->manakai_to_string;
      } @result;
      test {
        is $result, "abcdeffoo bar 123";
      } $c;
      undef $server;
    });
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 1, name => 'certificate_manager';

test {
  my $c = shift;

  my $port = find_listenable_port;
  my $host = Web::Host->parse_string ('127.0.0.1');

  my $gen = Web::Transport::PKI::Generator->new;
  return $gen->create_rsa_key->then (sub {
    my $ca_rsa = $_[0];
    return $gen->create_certificate (
      rsa => $ca_rsa,
      ca_rsa => $ca_rsa,
      subject => {O => 'The Root CA'},
      issuer => {O => 'The Root CA'},
      not_before => time - 60,
      not_after => time + 3600,
      serial_number => 1,
      ca => 1,
    )->then (sub {
      my $ca_cert = $_[0];
      return $gen->create_rsa_key->then (sub {
        my $rsa = $_[0];
        return $gen->create_certificate (
          rsa => $rsa,
          ca_rsa => $ca_rsa,
          ca_cert => $ca_cert,
          not_before => time - 30,
          not_after => time + 3000,
          serial_number => 2,
          subject => {CN => 'server.test'},
          san_hosts => [$host],
          ee => 1,
        )->then (sub {
          my $cert = $_[0];
          return [$ca_cert, $ca_rsa, $cert, $rsa];
        });
      });
    });
  })->then (sub {
    my ($ca_cert, $ca_rsa, $cert, $rsa) = @{$_[0]};

    my $cm1 = Web::Transport::DefaultCertificateManager->new ({
      ca_cert => $ca_cert,
    });

    socket my $sock, Socket::PF_INET, Socket::SOCK_STREAM, 0;
    Web::Transport::TLSStream->create ({
      server => 1,
      certificate_manager => $cm1,
      parent => {
        class => 'Web::Transport::TCPStream',
        server => 1,
        fh => $sock,
        host => $host,
        port => $port,
      },
    })->then (sub { test { ok 0 } $c }, sub {
      my $e = $_[0];
      test {
        isa_ok $e, 'Web::Transport::TypeError';
        is $e->name, 'TypeError';
        is $e->message, 'Bad |cert|';
        is $e->file_name, __FILE__;
        is $e->line_number, __LINE__+2;
      } $c;
    });
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 5, name => 'certificate_manager, not for server';

test {
  my $c = shift;

  my $port = find_listenable_port;
  my $host = Web::Host->parse_string ('127.0.0.1');
  my $domain = Web::Host->parse_string ('foo.bar.test');

  my $gen = Web::Transport::PKI::Generator->new;
  return $gen->create_rsa_key->then (sub {
    my $ca_rsa = $_[0];
    return $gen->create_certificate (
      rsa => $ca_rsa,
      ca_rsa => $ca_rsa,
      subject => {O => 'The Root CA'},
      issuer => {O => 'The Root CA'},
      not_before => time - 60,
      not_after => time + 3600,
      serial_number => 1,
      ca => 1,
    )->then (sub {
      my $ca_cert = $_[0];
      return $gen->create_rsa_key->then (sub {
        my $rsa = $_[0];
        return $gen->create_certificate (
          rsa => $rsa,
          ca_rsa => $ca_rsa,
          ca_cert => $ca_cert,
          not_before => time - 30,
          not_after => time + 3000,
          serial_number => 2,
          subject => {CN => 'server.test'},
          san_hosts => [$domain],
          ee => 1,
        )->then (sub {
          my $cert = $_[0];
          return [$ca_cert, $ca_rsa, $cert, $rsa];
        });
      });
    });
  })->then (sub {
    my ($ca_cert, $ca_rsa, $cert, $rsa) = @{$_[0]};

    my $cm1 = Web::Transport::DefaultCertificateManager->new ({
      ca_cert => $ca_cert,
      cert => $cert,
      key => $rsa,
    });

    my $server = tcp_server undef, $port, sub {
      Web::Transport::TLSStream->create ({
        server => 1,
        certificate_manager => $cm1,
        parent => {
          class => 'Web::Transport::TCPStream',
          server => 1,
          fh => $_[0],
          host => Web::Host->parse_string ($_[1]),
          port => $_[2],
        },
      })->then (sub {
        my $info = $_[0];

        my $w = $info->{writable}->get_writer;
        my $r = $info->{readable}->get_reader ('byob');
        return promised_until {
          return $r->read (dv "x" x 10)->then (sub {
            my $v = $_[0];
            if ($v->{done}) {
              $w->close;
              return $info->{closed}->then (sub { return 1 });
            } else {
              $w->write ($v->{value});
              return 0;
            }
          });
        };
      });
    }; # $server

    my $cm2 = Web::Transport::DefaultCertificateManager->new ({
      ca_cert => $ca_cert,
    });

    my @result;
    return Web::Transport::TLSStream->create ({
      host => $domain,
      certificate_manager => $cm2,
      parent => {
        class => 'Web::Transport::TCPStream',
        host => $host,
        port => $port,
      },
    })->then (sub {
      my $info = $_[0];
      my $w = $info->{writable}->get_writer;
      my $r = $info->{readable}->get_reader ('byob');

      $w->write (dv "abcdef");
      $w->write (dv "foo bar 123");
      $w->close;

      return promised_until {
        return $r->read (dv "x" x 10)->then (sub {
          my $v = $_[0];
          if ($v->{done}) {
            return $info->{closed}->then (sub { return 1 });
          } else {
            push @result, $v->{value};
            return 0;
          }
        });
      };
    })->then (sub {
      my $result = join '', map {
        $_->manakai_to_string;
      } @result;
      test {
        is $result, "abcdeffoo bar 123";
      } $c;
      undef $server;
    });
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 1, name => 'certificate_manager, SNI domain name';

test {
  my $c = shift;

  my $port = find_listenable_port;
  my $host = Web::Host->parse_string ('127.0.0.1');
  my $domain = Web::Host->parse_string ('foo.bar.test');

  my $gen = Web::Transport::PKI::Generator->new;
  return $gen->create_rsa_key->then (sub {
    my $ca_rsa = $_[0];
    return $gen->create_certificate (
      rsa => $ca_rsa,
      ca_rsa => $ca_rsa,
      subject => {O => 'The Root CA'},
      issuer => {O => 'The Root CA'},
      not_before => time - 60,
      not_after => time + 3600,
      serial_number => 1,
      ca => 1,
    )->then (sub {
      my $ca_cert = $_[0];
      return Promise->all ([
        $gen->create_rsa_key,
        $gen->create_rsa_key,
      ])->then (sub {
        my $rsa = $_[0]->[0];
        my $rsa2 = $_[0]->[1];
        return Promise->all ([
          $gen->create_certificate (
            rsa => $rsa,
            ca_rsa => $ca_rsa,
            ca_cert => $ca_cert,
            not_before => time - 30,
            not_after => time + 3000,
            serial_number => 2,
            subject => {CN => 'server.test'},
            san_hosts => [$host],
            ee => 1,
          ),
          $gen->create_certificate (
            rsa => $rsa2,
            ca_rsa => $ca_rsa,
            ca_cert => $ca_cert,
            not_before => time - 30,
            not_after => time + 3000,
            serial_number => 2,
            subject => {CN => 'server.test'},
            san_hosts => [$domain],
            ee => 1,
          ),
        ])->then (sub {
          my $cert = $_[0]->[0];
          my $cert2 = $_[0]->[1];
          return [$ca_cert, $ca_rsa, $cert, $rsa, $cert2, $rsa2];
        });
      });
    });
  })->then (sub {
    my ($ca_cert, $ca_rsa, $cert, $rsa, $cert2, $rsa2) = @{$_[0]};

    {
      package test::CM1;
      push our @ISA, qw(Web::Transport::DefaultCertificateManager);
      sub to_anyevent_tls_args_for_host_sync {
        return $_[0]->{sni}->{$_[1]->to_ascii};
      }
    }

    my $cm1 = test::CM1->new ({
      ca_cert => $ca_cert,
      cert => $cert,
      key => $rsa,
    });
    $cm1->{sni} = {
      $domain->to_ascii => {
        cert => $cert2->to_pem,
        key => $rsa2->to_pem,
      },
    };

    my $server = tcp_server undef, $port, sub {
      Web::Transport::TLSStream->create ({
        server => 1,
        certificate_manager => $cm1,
        parent => {
          class => 'Web::Transport::TCPStream',
          server => 1,
          fh => $_[0],
          host => Web::Host->parse_string ($_[1]),
          port => $_[2],
        },
      })->then (sub {
        my $info = $_[0];

        my $w = $info->{writable}->get_writer;
        my $r = $info->{readable}->get_reader ('byob');
        return promised_until {
          return $r->read (dv "x" x 10)->then (sub {
            my $v = $_[0];
            if ($v->{done}) {
              $w->close;
              return $info->{closed}->then (sub { return 1 });
            } else {
              $w->write ($v->{value});
              return 0;
            }
          });
        };
      });
    }; # $server

    my $cm2 = Web::Transport::DefaultCertificateManager->new ({
      ca_cert => $ca_cert,
    });

    my @result;
    return Web::Transport::TLSStream->create ({
      host => $domain,
      certificate_manager => $cm2,
      parent => {
        class => 'Web::Transport::TCPStream',
        host => $host,
        port => $port,
      },
    })->then (sub {
      my $info = $_[0];
      my $w = $info->{writable}->get_writer;
      my $r = $info->{readable}->get_reader ('byob');

      $w->write (dv "abcdef");
      $w->write (dv "foo bar 123");
      $w->close;

      return promised_until {
        return $r->read (dv "x" x 10)->then (sub {
          my $v = $_[0];
          if ($v->{done}) {
            return $info->{closed}->then (sub { return 1 });
          } else {
            push @result, $v->{value};
            return 0;
          }
        });
      };
    })->then (sub {
      my $result = join '', map {
        $_->manakai_to_string;
      } @result;
      test {
        is $result, "abcdeffoo bar 123";
      } $c;
      undef $server;
    });
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 1, name => 'certificate_manager, SNI domain name certificate';

test {
  my $c = shift;

  my $port = find_listenable_port;
  my $host = Web::Host->parse_string ('127.0.0.1');
  my $domain = Web::Host->parse_string ('foo.bar.test');

  my $gen = Web::Transport::PKI::Generator->new;
  return $gen->create_rsa_key->then (sub {
    my $ca_rsa = $_[0];
    return $gen->create_certificate (
      rsa => $ca_rsa,
      ca_rsa => $ca_rsa,
      subject => {O => 'The Root CA'},
      issuer => {O => 'The Root CA'},
      not_before => time - 60,
      not_after => time + 3600,
      serial_number => 1,
      ca => 1,
    )->then (sub {
      my $ca_cert = $_[0];
      return $gen->create_rsa_key->then (sub {
        my $rsa = $_[0];
        return $gen->create_certificate (
          rsa => $rsa,
          ca_rsa => $ca_rsa,
          ca_cert => $ca_cert,
          not_before => time - 30,
          not_after => time + 3000,
          serial_number => 2,
          subject => {CN => 'server.test'},
          san_hosts => [$host],
          ee => 1,
        )->then (sub {
          my $cert = $_[0];
          return [$ca_cert, $ca_rsa, $cert, $rsa];
        });
      });
    });
  })->then (sub {
    my ($ca_cert, $ca_rsa, $cert, $rsa) = @{$_[0]};

    {
      package test::CM3;
      push our @ISA, qw(Web::Transport::DefaultCertificateManager);
      sub to_anyevent_tls_args_sync {
        return {};
      }
    }

    my $cm1 = test::CM3->new ({
      ca_cert => $ca_cert,
      cert => $cert,
      key => $rsa,
    });

    my @p;
    my $server = tcp_server undef, $port, sub {
      push @p, Web::Transport::TLSStream->create ({
        server => 1,
        certificate_manager => $cm1,
        parent => {
          class => 'Web::Transport::TCPStream',
          server => 1,
          fh => $_[0],
          host => Web::Host->parse_string ($_[1]),
          port => $_[2],
        },
      })->then (sub { test { ok 0 } $c }, sub {
        my $e = $_[0];
        test {
          isa_ok $e, 'Web::Transport::TypeError', $e;
          is $e->name, 'TypeError';
          is $e->message, 'Bad |cert|';
          is $e->file_name, __FILE__;
          is $e->line_number, __LINE__+2;
        } $c;
      });
    };

    my $cm2 = Web::Transport::DefaultCertificateManager->new ({
      ca_cert => $ca_cert,
    });

    return Web::Transport::TLSStream->create ({
      host => $domain,
      certificate_manager => $cm2,
      parent => {
        class => 'Web::Transport::TCPStream',
        host => $host,
        port => $port,
      },
    })->then (sub { test { ok 0 } $c }, sub {
      my $e = $_[0];
      test {
        isa_ok $e, 'Web::Transport::ProtocolError', $e;
      } $c;
      undef $server;
      return Promise->all (\@p);
    });
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 6, name => 'certificate_manager, no server certificate returned by certificate manager';

test {
  my $c = shift;

  my $port = find_listenable_port;
  my $host = Web::Host->parse_string ('127.0.0.1');
  my $domain = Web::Host->parse_string ('foo.bar.test');

  my $gen = Web::Transport::PKI::Generator->new;
  return $gen->create_rsa_key->then (sub {
    my $ca_rsa = $_[0];
    return $gen->create_certificate (
      rsa => $ca_rsa,
      ca_rsa => $ca_rsa,
      subject => {O => 'The Root CA'},
      issuer => {O => 'The Root CA'},
      not_before => time - 60,
      not_after => time + 3600,
      serial_number => 1,
      ca => 1,
    )->then (sub {
      my $ca_cert = $_[0];
      return $gen->create_rsa_key->then (sub {
        my $rsa = $_[0];
        return $gen->create_certificate (
          rsa => $rsa,
          ca_rsa => $ca_rsa,
          ca_cert => $ca_cert,
          not_before => time - 30,
          not_after => time + 3000,
          serial_number => 2,
          subject => {CN => 'server.test'},
          san_hosts => [$host],
          ee => 1,
        )->then (sub {
          my $cert = $_[0];
          return [$ca_cert, $ca_rsa, $cert, $rsa];
        });
      });
    });
  })->then (sub {
    my ($ca_cert, $ca_rsa, $cert, $rsa) = @{$_[0]};

    {
      package test::CM2;
      push our @ISA, qw(Web::Transport::DefaultCertificateManager);
      sub to_anyevent_tls_args_for_host_sync {
        return {};
      }
    }

    my $cm1 = test::CM2->new ({
      ca_cert => $ca_cert,
      cert => $cert,
      key => $rsa,
    });

    my @p;
    my $server = tcp_server undef, $port, sub {
      push @p, Web::Transport::TLSStream->create ({
        server => 1,
        certificate_manager => $cm1,
        parent => {
          class => 'Web::Transport::TCPStream',
          server => 1,
          fh => $_[0],
          host => Web::Host->parse_string ($_[1]),
          port => $_[2],
        },
      })->then (sub { test { ok 0 } $c }, sub {
        my $e = $_[0];
        test {
          isa_ok $e, 'Web::Transport::TypeError', $e;
          is $e->name, 'TypeError';
          is $e->message, 'Bad |cert|';
          is $e->file_name, __FILE__;
          is $e->line_number, __LINE__+2;
        } $c;
      });
    };


    my $cm2 = Web::Transport::DefaultCertificateManager->new ({
      ca_cert => $ca_cert,
    });

    return Web::Transport::TLSStream->create ({
      host => $domain,
      certificate_manager => $cm2,
      parent => {
        class => 'Web::Transport::TCPStream',
        host => $host,
        port => $port,
      },
    })->then (sub { test { ok 0 } $c }, sub {
      my $e = $_[0];
      test {
        isa_ok $e, 'Web::Transport::ProtocolError', $e;
      } $c;
      undef $server;
      return Promise->all (\@p);
    });
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 6, name => 'certificate_manager, no SNI server certificate';

test {
  my $c = shift;

  my $port = find_listenable_port;
  my $host = Web::Host->parse_string ('127.0.0.1');
  my $domain = Web::Host->parse_string ('foo.bar.test');

  my $gen = Web::Transport::PKI::Generator->new;
  return $gen->create_rsa_key->then (sub {
    my $ca_rsa = $_[0];
    return $gen->create_certificate (
      rsa => $ca_rsa,
      ca_rsa => $ca_rsa,
      subject => {O => 'The Root CA'},
      issuer => {O => 'The Root CA'},
      not_before => time - 60,
      not_after => time + 3600,
      serial_number => 1,
      ca => 1,
    )->then (sub {
      my $ca_cert = $_[0];
      return $gen->create_rsa_key->then (sub {
        my $rsa = $_[0];
        return $gen->create_certificate (
          rsa => $rsa,
          ca_rsa => $ca_rsa,
          ca_cert => $ca_cert,
          not_before => time - 30,
          not_after => time + 3000,
          serial_number => 2,
          subject => {CN => 'server.test'},
          san_hosts => [$host],
          ee => 1,
        )->then (sub {
          my $cert = $_[0];
          return [$ca_cert, $ca_rsa, $cert, $rsa];
        });
      });
    });
  })->then (sub {
    my ($ca_cert, $ca_rsa, $cert, $rsa) = @{$_[0]};

    {
      package test::CM4;
      push our @ISA, qw(Web::Transport::DefaultCertificateManager);
      sub to_anyevent_tls_args_for_host_sync {
        die "bhseheshse";
      }
    }

    my $cm1 = test::CM4->new ({
      ca_cert => $ca_cert,
      cert => $cert,
      key => $rsa,
    });

    my @p;
    my $server = tcp_server undef, $port, sub {
      push @p, Web::Transport::TLSStream->create ({
        server => 1,
        certificate_manager => $cm1,
        parent => {
          class => 'Web::Transport::TCPStream',
          server => 1,
          fh => $_[0],
          host => Web::Host->parse_string ($_[1]),
          port => $_[2],
        },
      })->then (sub { test { ok 0 } $c }, sub {
        my $e = $_[0];
        test {
          isa_ok $e, 'Web::Transport::Error', $e;
          is $e->name, 'Error';
          like $e->message, qr{^bhseheshse at \Q@{[__FILE__]}\E line \Q@{[__LINE__-27]}\E};
          is $e->file_name, __FILE__;
          is $e->line_number, __LINE__+2;
        } $c;
      });
    };

    my $cm2 = Web::Transport::DefaultCertificateManager->new ({
      ca_cert => $ca_cert,
    });

    return Web::Transport::TLSStream->create ({
      host => $domain,
      certificate_manager => $cm2,
      parent => {
        class => 'Web::Transport::TCPStream',
        host => $host,
        port => $port,
      },
    })->then (sub { test { ok 0 } $c }, sub {
      my $e = $_[0];
      test {
        isa_ok $e, 'Web::Transport::ProtocolError', $e;
      } $c;
      undef $server;
      return Promise->all (\@p);
    });
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 6, name => 'certificate_manager, throw by server certificate';

test {
  my $c = shift;

  my $port = find_listenable_port;
  my $host = Web::Host->parse_string ('127.0.0.1');
  my $domain = Web::Host->parse_string ('foo.bar.test');

  my $gen = Web::Transport::PKI::Generator->new;
  return $gen->create_rsa_key->then (sub {
    my $ca_rsa = $_[0];
    return $gen->create_certificate (
      rsa => $ca_rsa,
      ca_rsa => $ca_rsa,
      subject => {O => 'The Root CA'},
      issuer => {O => 'The Root CA'},
      not_before => time - 60,
      not_after => time + 3600,
      serial_number => 1,
      ca => 1,
    )->then (sub {
      my $ca_cert = $_[0];
      return $gen->create_rsa_key->then (sub {
        my $rsa = $_[0];
        return $gen->create_certificate (
          rsa => $rsa,
          ca_rsa => $ca_rsa,
          ca_cert => $ca_cert,
          not_before => time - 30,
          not_after => time + 3000,
          serial_number => 2,
          subject => {CN => 'server.test'},
          san_hosts => [$host],
          ee => 1,
        )->then (sub {
          my $cert = $_[0];
          return [$ca_cert, $ca_rsa, $cert, $rsa];
        });
      });
    });
  })->then (sub {
    my ($ca_cert, $ca_rsa, $cert, $rsa) = @{$_[0]};

    my $x = $test::CM5::X = Web::Transport::TypeError->new (rand);
    {
      package test::CM5;
      push our @ISA, qw(Web::Transport::DefaultCertificateManager);
      sub to_anyevent_tls_args_for_host_sync {
        die $test::CM5::X;
      }
    }

    my $cm1 = test::CM5->new ({
      ca_cert => $ca_cert,
      cert => $cert,
      key => $rsa,
    });

    my @p;
    my $server = tcp_server undef, $port, sub {
      push @p, Web::Transport::TLSStream->create ({
        server => 1,
        certificate_manager => $cm1,
        parent => {
          class => 'Web::Transport::TCPStream',
          server => 1,
          fh => $_[0],
          host => Web::Host->parse_string ($_[1]),
          port => $_[2],
        },
      })->then (sub { test { ok 0 } $c }, sub {
        my $e = $_[0];
        test {
          is $e, $x;
        } $c;
      });
    };

    my $cm2 = Web::Transport::DefaultCertificateManager->new ({
      ca_cert => $ca_cert,
    });

    return Web::Transport::TLSStream->create ({
      host => $domain,
      certificate_manager => $cm2,
      parent => {
        class => 'Web::Transport::TCPStream',
        host => $host,
        port => $port,
      },
    })->then (sub { test { ok 0 } $c }, sub {
      my $e = $_[0];
      test {
        isa_ok $e, 'Web::Transport::ProtocolError', $e;
      } $c;
      undef $server;
      return Promise->all (\@p);
    });
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 2, name => 'certificate_manager, exception by server certificate';

test {
  my $c = shift;

  my $port = find_listenable_port;
  my $host = Web::Host->parse_string ('127.0.0.1');
  my $domain = Web::Host->parse_string ('foo.bar.test');

  my $gen = Web::Transport::PKI::Generator->new;
  return $gen->create_rsa_key->then (sub {
    my $ca_rsa = $_[0];
    return $gen->create_certificate (
      rsa => $ca_rsa,
      ca_rsa => $ca_rsa,
      subject => {O => 'The Root CA'},
      issuer => {O => 'The Root CA'},
      not_before => time - 60,
      not_after => time + 3600,
      serial_number => 1,
      ca => 1,
    )->then (sub {
      my $ca_cert = $_[0];
      return $gen->create_rsa_key->then (sub {
        my $rsa = $_[0];
        return $gen->create_certificate (
          rsa => $rsa,
          ca_rsa => $ca_rsa,
          ca_cert => $ca_cert,
          not_before => time - 30,
          not_after => time + 3000,
          serial_number => 2,
          subject => {CN => 'server.test'},
          san_hosts => [$host],
          ee => 1,
        )->then (sub {
          my $cert = $_[0];
          return [$ca_cert, $ca_rsa, $cert, $rsa];
        });
      });
    });
  })->then (sub {
    my ($ca_cert, $ca_rsa, $cert, $rsa) = @{$_[0]};

    my $x = $test::CM6::X = Web::Transport::TypeError->new (rand);
    {
      package test::CM6;
      push our @ISA, qw(Web::Transport::DefaultCertificateManager);
      sub prepare {
        die $test::CM6::X;
      }
    }

    my $cm1 = test::CM6->new ({
      ca_cert => $ca_cert,
      cert => $cert,
      key => $rsa,
    });

    my @p;
    my $server = tcp_server undef, $port, sub {
      push @p, Web::Transport::TLSStream->create ({
        server => 1,
        certificate_manager => $cm1,
        parent => {
          class => 'Web::Transport::TCPStream',
          server => 1,
          fh => $_[0],
          host => Web::Host->parse_string ($_[1]),
          port => $_[2],
        },
      })->then (sub { test { ok 0 } $c }, sub {
        my $e = $_[0];
        test {
          is $e, $x, "server create exception ($e)";
        } $c;
      });
    };

    my $cm2 = Web::Transport::DefaultCertificateManager->new ({
      ca_cert => $ca_cert,
    });

    return Web::Transport::TLSStream->create ({
      host => $domain,
      certificate_manager => $cm2,
      parent => {
        class => 'Web::Transport::TCPStream',
        host => $host,
        port => $port,
      },
    })->then (sub { test { ok 0 } $c }, sub {
      my $e = $_[0];
      test {
        if (UNIVERSAL::isa ($e, 'Streams::IOError')) {
          isa_ok $e, 'Streams::IOError', $e;
        } else {
          isa_ok $e, 'Web::Transport::ProtocolError', $e;
        }
      } $c;
      undef $server;
      return Promise->all (\@p);
    });
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 2, name => 'certificate_manager, exception in server CM prepare, 1';

test {
  my $c = shift;

  my $port = find_listenable_port;
  my $host = Web::Host->parse_string ('127.0.0.1');
  my $domain = Web::Host->parse_string ('foo.bar.test');

  my $gen = Web::Transport::PKI::Generator->new;
  return $gen->create_rsa_key->then (sub {
    my $ca_rsa = $_[0];
    return $gen->create_certificate (
      rsa => $ca_rsa,
      ca_rsa => $ca_rsa,
      subject => {O => 'The Root CA'},
      issuer => {O => 'The Root CA'},
      not_before => time - 60,
      not_after => time + 3600,
      serial_number => 1,
      ca => 1,
    )->then (sub {
      my $ca_cert = $_[0];
      return $gen->create_rsa_key->then (sub {
        my $rsa = $_[0];
        return $gen->create_certificate (
          rsa => $rsa,
          ca_rsa => $ca_rsa,
          ca_cert => $ca_cert,
          not_before => time - 30,
          not_after => time + 3000,
          serial_number => 2,
          subject => {CN => 'server.test'},
          san_hosts => [$host],
          ee => 1,
        )->then (sub {
          my $cert = $_[0];
          return [$ca_cert, $ca_rsa, $cert, $rsa];
        });
      });
    });
  })->then (sub {
    my ($ca_cert, $ca_rsa, $cert, $rsa) = @{$_[0]};

    my $x = $test::CM7::X = Web::Transport::TypeError->new (rand);
    {
      package test::CM7;
      push our @ISA, qw(Web::Transport::DefaultCertificateManager);
      sub prepare {
        die $test::CM7::X;
      }
    }

    my $cm1 = test::CM7->new ({
      ca_cert => $ca_cert,
      cert => $cert,
      key => $rsa,
    });

    my @p;
    my $fh;
    my $server = tcp_server undef, $port, sub {
      push @p, Web::Transport::TLSStream->create ({
        server => 1,
        certificate_manager => $cm1,
        parent => {
          class => 'Web::Transport::TCPStream',
          server => 1,
          fh => $fh = $_[0],
          host => Web::Host->parse_string ($_[1]),
          port => $_[2],
        },
      })->then (sub { test { ok 0 } $c }, sub {
        my $e = $_[0];
        test {
          is $e, $x, "server create exception ($e)";
        } $c;
      });
    };

    my $cm2 = Web::Transport::DefaultCertificateManager->new ({
      ca_cert => $ca_cert,
    });

    return Web::Transport::TLSStream->create ({
      host => $domain,
      certificate_manager => $cm2,
      parent => {
        class => 'Web::Transport::TCPStream',
        host => $host,
        port => $port,
      },
    })->then (sub { test { ok 0 } $c }, sub {
      my $e = $_[0];
      test {
        isa_ok $e, 'Web::Transport::ProtocolError', $e;
      } $c;
      undef $server;
      return Promise->all (\@p);
    });
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 2, name => 'certificate_manager, exception in server CM prepare, 2';

Test::Certificates->wait_create_cert;
run_tests;

=head1 LICENSE

Copyright 2017-2024 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
