use strict;
use warnings;
use Path::Tiny;
use lib glob path (__FILE__)->parent->parent->parent->child ('t_deps/modules/*/lib');
use Promise;
use Promised::Flow;
use Web::Encoding;
use Web::URL;
use Web::Transport::TCPTransport;
use Web::Transport::PlatformResolver;
use Test::More;
use Test::X1;
use Test::HTCT::Parser;

my $url = Web::URL->parse_string (shift || die "Usage: $0 url [mode]");
my $mode = shift || ''; # or 'apache' or 'nginx'

my $host = $url->host;
my $port = $url->port;
unless (defined $port) {
  $port = 80 if $url->scheme eq 'http';
  $port = 443 if $url->scheme eq 'https';
}
my $hostport = $url->hostport;

my $test_data_path = path (__FILE__)->parent->parent->parent->child ('t_deps/data-server');

my $Texts = {};

my $Something = qr{(?:(?!</html>)[\s\S])+?};
my $HTTPHeader = sub { return qr{HTTP/1.1 (?:$_[0])\x0D
(?:(?:(?!</html>)[^\x0A\x0D])+\x0D?\x0A)+} };
my $HTMLBody = sub { return qr{<$Something(?:$_[0])$Something</html>\x0D?
} };

for (
  ['400', q{400 Bad Request}, '400'],
  ['404', q{404 Not Found}, '404'],
  ['404nohost', q{404 Not Found|301 Moved Permanently}, '404|301'],
  ['405', q{405 (?:Method |)Not Allowed|501 Not Implemented}, '405|501'],
  ['408', q{408 Request Timeout}, '408'],
  ['411', q{411 Length Required}, '411'],
  ['414', q{414 Request-URI Too (?:Large|Long)}, '414'],
  ['500', q{500 Internal Server Error}, '500'],
  ['501', q{501 Not Implemented}, '501'],
) {
  $Texts->{$_->[0].'header'} = $HTTPHeader->($_->[1]);
  $Texts->{$_->[0].'body'} = $HTMLBody->($_->[2]);
  $Texts->{$_->[0].'h'} = qr{$Texts->{$_->[0].'header'}\x0D\x0A$Texts->{$_->[0].'body'}};
}

$Texts->{eof} = qr{\[\[EOF\]\]};
$Texts->{timeout} = qr{\[\[timeout\]\]};

for my $path ($test_data_path->children (qr/\.dat\z/)) {
  for_each_test $path, {
    input => {is_prefixed => 1},
    result => {is_prefixed => 1},
    'result-apache' => {is_prefixed => 1},
  }, sub {
    my $test = $_[0];
    test {
      my $c = $_[0];
      my @timer;

      my $commands = [];
      for (split /\x0A/, $test->{input}->[0]) {
        if (/^"([^"]+)"$/) {
          push @$commands, {type => 'send', value => $1};
          $commands->[-1]->{value} =~ s/\\x([0-9A-Fa-f]{2})/pack 'C', hex $1/ge;
      } elsif (/^"([^"]+)" x ([0-9]+)$/) {
        my $v = $1;
        my $n = $2;
        $v =~ s/\\x([0-9A-Fa-f]{2})/pack 'C', hex $1/ge;
        $v = $v x ($n);
        push @$commands, {type => 'send', value => $v};
      } elsif (/^"([^"]+)"LF$/) {
        push @$commands, {type => 'send', value => $1."\x0A"};
        $commands->[-1]->{value} =~ s/\\x([0-9A-Fa-f]{2})/pack 'C', hex $1/ge;
      } elsif (/^"([^"]+)"CRLF$/) {
        push @$commands, {type => 'send', value => $1."\x0D\x0A"};
        $commands->[-1]->{value} =~ s/\\x([0-9A-Fa-f]{2})/pack 'C', hex $1/ge;
      } elsif (/^CR$/) {
        push @$commands, {type => 'send', value => "\x0D"};
      } elsif (/^LF$/) {
        push @$commands, {type => 'send', value => "\x0A"};
      } elsif (/^CRLF$/) {
        push @$commands, {type => 'send', value => "\x0D\x0A"};
      } elsif (/^hostport$/) {
        push @$commands, {type => 'send', value => $hostport};
      } elsif (/^close$/) {
        push @$commands, {type => 'close'};
      } elsif (/^sleep\s+(\d+)$/) {
        push @$commands, {type => 'sleep', value => $1};
      } elsif (/^timeout\s+(\d+)$/) {
        push @$commands, {type => 'timeout', value => $1};
      } elsif (/^receive\s+CRLFCRLF$/) {
        push @$commands, {type => 'receive', value => "\x0D\x0A\x0D\x0A"};
      } elsif (/^receive\s+"([^"]+)"$/) {
        push @$commands, {type => 'receive', value => $1};
        $commands->[-1]->{value} =~ s/\\x([0-9A-Fa-f]{2})/pack 'C', hex $1/ge;
      } elsif (/^\s*#/) {
        #
      } elsif (/\S/) {
        die "Bad line |$_|";
      }
    }

      my $expected_o = $test->{'result-' . $mode}->[0] || $test->{result}->[0];
      my $expected = $expected_o;
      $expected =~ s{\{\{([\w|]+)\}\}}{
        '(' . (join '|', map { "(?:$_)" } map {
          $Texts->{$_} // die "Unknown text |$_|";
        } split /\|/, $1) . ')';
      }ge;
      $expected = qr/\A(?:$expected)\z/;

    my $received_data = '';
    Web::Transport::PlatformResolver->new->resolve ($host)->then (sub {
      my $transport = Web::Transport::TCPTransport->new
          (host => $_[0], port => $port);

      my ($end_ok, $end_ng);
      my $end_p = Promise->new (sub { ($end_ok, $end_ng) = @_ });
      my $reof;
      my $cend;
      my $write_closed;

      #warn "Started";
      #warn scalar gmtime;
      my $p = $transport->start (sub {
        my ($transport, $type) = @_;
        if ($type eq 'readdata') {
          #warn "Received |${$_[2]}|";
          #warn scalar gmtime;
          $received_data .= ${$_[2]};
        } elsif ($type eq 'readeof') {
          #my $data = $_[2];
          #warn "Received EOF";
          #warn scalar gmtime;
          $received_data .= '[[EOF]]';
          $reof = 1;
          if ($cend) {
            $transport->push_shutdown unless $write_closed;
          }
        } elsif ($type eq 'writeeof') {
          #warn "Sent EOF";
          #warn scalar gmtime;
          $write_closed = 1;
        } elsif ($type eq 'close') {
          #warn "Closed";
          #warn scalar gmtime;
          $end_ok->();
        }
      })->then (sub {
        #warn "Established";
        #warn scalar gmtime;

        promised_for {
          my $command = $_[0];
          if ($command->{type} eq 'send') {
            $transport->push_write (\(encode_web_utf8 $command->{value}));
          } elsif ($command->{type} eq 'close') {
            $transport->push_shutdown;
            $write_closed = 1;
          } elsif ($command->{type} eq 'sleep') {
            return promised_sleep $command->{value};
          } elsif ($command->{type} eq 'timeout') {
            my $timer; $timer = AE::timer $command->{value}, 0, sub {
              $timer = undef;
              $received_data .= '[[timeout]]';
              $transport->abort (message => "Timeout ($command->{value})");
            };
            push @timer, \$timer;
          } elsif ($command->{type} eq 'receive') {
            return promised_wait_until {
              #warn "Waiting |$command->{value}| (Data: |$received_data|)";
              return $received_data =~ /\Q$command->{value}\E/;
            };
          } else {
            die "Unknown command |$command->{type}|";
          }
          } $commands;
        })->then (sub {
          $cend = 1;
          if ($reof) {
            return $transport->push_shutdown;
          }
        })->catch (sub {
          my $error = $_[0];
          #warn "Error |$error|";
          #warn scalar gmtime;
          $transport->abort if defined $transport;
          $end_ng->($error);
        });

        return promised_cleanup { $transport->abort; undef $transport } $end_p;
      })->then (sub {
        test {
          like $received_data, $expected, $expected_o;
        } $c;
      }, sub {
        my $error = $_[0];
        test {
          is $error, undef;
          ok 0;
        } $c;
      })->then (sub {
        done $c;
        undef $c;
        $$_ = undef for @timer;
      });
    } n => 1, name => [$path, $test->{name}->[0]], timeout => 90;
  };
} # $path

run_tests;

=head1 LICENSE

Copyright 2016 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
