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
use Web::Transport::SOCKS4Stream;
use AbortController;
use Web::Transport::FindPort;

test {
  my $c = shift;

  my $port = find_listenable_port;
  my $host = Web::Host->parse_string ('255.0.0.1');

  my $ac = new AbortController;
  promised_sleep (1)->then (sub {
    $ac->abort;
  });

  my $real_host = Web::Host->parse_string ('10.44.13.111');
  my $real_port = 1 + int rand 10000;

  Web::Transport::SOCKS4Stream->create ({
    host => $real_host,
    port => $real_port,
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
      is $e->line_number, __LINE__-26;
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

  my $real_host = Web::Host->parse_string ('10.44.13.111');
  my $real_port = 1 + int rand 10000;

  Web::Transport::SOCKS4Stream->create ({
    host => $real_host,
    port => $real_port,
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
      is $e->line_number, __LINE__-25;
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

  Web::Transport::SOCKS4Stream->create ({
    host => $real_host,
    port => $real_port,
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

run_tests;

=head1 LICENSE

Copyright 2017-2018 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
