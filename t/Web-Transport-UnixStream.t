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
use Web::Transport::UnixStream;

sub dv ($) {
  return DataView->new (ArrayBuffer->new_from_scalarref (\($_[0])));
} # dv

my $test_path = path (__FILE__)->parent->parent->child ('local/test')->absolute;
$test_path->mkpath;

sub find_unix_path () {
  return $test_path->child (int (rand 10000) + 1024);
} # find_unix_path

sub unix_server ($$) {
  return tcp_server ('unix/', $_[0], $_[1]);
} # unix_server

{
  package test::DestroyCallback1;
  sub DESTROY {
    $_[0]->();
  }
}

test {
  my $c = shift;
  Web::Transport::UnixStream->create ({server => 1})->catch (sub {
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
  Web::Transport::UnixStream->create ({})->catch (sub {
    my $e = $_[0];
    test {
      is $e->name, 'TypeError';
      is $e->message, 'Bad |path|';
      is $e->file_name, __FILE__;
      is $e->line_number, __LINE__+4;
    } $c;
    done $c;
    undef $c;
  });
} n => 4, name => 'create no |path|';

test {
  my $c = shift;

  my $path = find_unix_path;

  my $destroyed = 0;

  my $server = unix_server $path, sub {
    Web::Transport::UnixStream->create ({
      server => 1,
      fh => $_[0],
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

  Web::Transport::UnixStream->create ({
    path => $path,
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

  my $path = find_unix_path;

  my $destroyed = 0;
  my $server = unix_server $path, sub {
    Web::Transport::UnixStream->create ({
      server => 1,
      fh => $_[0],
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

  Web::Transport::UnixStream->create ({
    path => $path,
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

  my $path = find_unix_path;

  my $destroyed = 0;
  my $server = unix_server $path, sub {
    Web::Transport::UnixStream->create ({
      server => 1,
      fh => $_[0],
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

  Web::Transport::UnixStream->create ({
    path => $path,
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

  my $path = find_unix_path;

  my $destroyed = 0;
  my $server = unix_server $path, sub {
    Web::Transport::UnixStream->create ({
      server => 1,
      fh => $_[0],
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

  Web::Transport::UnixStream->create ({
    path => $path,
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

  my $path = find_unix_path;

  my $destroyed = 0;
  my $server = unix_server $path, sub {
    Web::Transport::UnixStream->create ({
      server => 1,
      fh => $_[0],
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

  Web::Transport::UnixStream->create ({
    path => $path,
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

  my $path = find_unix_path;

  my @done;

  my $destroyed = 0;
  my $server = unix_server $path, sub {
    Web::Transport::UnixStream->create ({
      server => 1,
      fh => $_[0],
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

  Web::Transport::UnixStream->create ({
    path => $path,
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

  my $path = find_unix_path;

  my $ac = new AbortController;
  $ac->abort;

  Web::Transport::UnixStream->create ({
    path => $path,
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
      is $e->line_number, __LINE__-16;
    } $c;
  })->then (sub {
    done $c;
    undef $c;
  });
} n => 5, name => 'abort connect before connect';

run_tests;

=head1 LICENSE

Copyright 2017-2018 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
