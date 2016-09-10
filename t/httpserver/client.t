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

$Texts->{'400header'} = qr{HTTP/1.1 (?:400 Bad Request)\x0D
(?:[^\x0A]+\x0A)+};
$Texts->{'400body'} = qr{<[\s\S]+?(?:400)[\s\S]+?</html>\x0D?
};
$Texts->{'400h'} = qr{$Texts->{'400header'}\x0D
$Texts->{'400body'}};

$Texts->{'404header'} = qr{HTTP/1.1 404 Not Found\x0D
(?:[^\x0A]+\x0A)+};
$Texts->{'404body'} = qr{<[\s\S]+?(?:404)[\s\S]+?</html>\x0D?
};
$Texts->{'404nohostbody'} = qr{<[\s\S]+?(?:404|301)[\s\S]+?</html>\x0D?
};
$Texts->{'404h'} = qr{$Texts->{'404header'}\x0D
$Texts->{'404body'}};
$Texts->{'404nohosth'} = qr{HTTP/1.1 (?:404 Not Found|301 Moved Permanently)\x0D
(?:[^\x0A]+\x0A)+\x0D
$Texts->{'404nohostbody'}};

$Texts->{'405body'} = qr{<[\s\S]+?(?:405|501)[\s\S]+?</html>\x0D?
};
$Texts->{'405h'} = qr{HTTP/1.1 (?:405 (?:Method |)Not Allowed|501 Not Implemented)\x0D
(?:[^\x0A]+\x0A)+\x0D
$Texts->{'405body'}};

$Texts->{'408h'} = qr{HTTP/1.1 408 Request Timeout\x0D
(?:[^\x0A]+\x0A)+\x0D
<[\s\S]+?(?:408)[\s\S]+?</html>\x0D?
};

$Texts->{'411header'} = qr{HTTP/1.1 411 Length Required\x0D
(?:[^\x0A]+\x0A)+};
$Texts->{'411h'} = qr{$Texts->{'411header'}\x0D
<[\s\S]+?(?:411)[\s\S]+?</html>\x0D?
};

$Texts->{'414body'} = qr{<[\s\S]+?(?:414)[\s\S]+?</html>\x0D?
};
$Texts->{'414h'} = qr{HTTP/1.1 (?:414 Request-URI Too (?:Large|Long))\x0D
(?:[^\x0A]+\x0A)+\x0D
$Texts->{'414body'}};

$Texts->{'500body'} = qr{<[\s\S]+?(?:500)[\s\S]+?</html>\x0D?
};

$Texts->{'501h'} = qr{HTTP/1.1 501 Not Implemented\x0D
(?:[^\x0A]+\x0A)+\x0D
<[\s\S]+?(?:501)[\s\S]+?</html>\x0D?
};

$Texts->{eof} = qr{\[\[EOF\]\]};

for my $path ($test_data_path->children (qr/\.dat\z/)) {
  for_each_test $path, {
    input => {is_prefixed => 1},
    result => {is_prefixed => 1},
    'result-apache' => {is_prefixed => 1},
  }, sub {
    my $test = $_[0];
    test {
      my $c = $_[0];

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
        } elsif ($type eq 'writeeof') {
          #warn "Sent EOF";
          #warn scalar gmtime;
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
          } elsif ($command->{type} eq 'sleep') {
            return promised_sleep $command->{value};
          } elsif ($command->{type} eq 'receive') {
            return promised_wait_until {
              #warn "Waiting |$command->{value}| (Data: |$received_data|)";
              return $received_data =~ /\Q$command->{value}\E/;
            };
          } else {
            die "Unknown command |$command->{type}|";
          }
        } $commands;
      }, sub {
        my $error = $_[0];
        #warn "Error |$error|";
        #warn scalar gmtime;
        $transport->abort;
        $end_ng->($error);
      });

        return $end_p;
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
