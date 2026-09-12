use strict;
use FindBin;
use lib glob "$FindBin::Bin/../modules/*/lib";
use lib glob "$FindBin::Bin/../t_deps/modules/*/lib";
use lib "$FindBin::Bin/../lib";
use warnings;
use Test::More;
use IO::Socket::INET;
use IO::Select;
use Socket qw(SOL_SOCKET SO_LINGER);
use POSIX ();
use Time::HiRes ();
use Scalar::Util qw(weaken);
use Promise;
use Web::URL;
use Web::Transport::BasicClient;
use Web::Transport::ConstProxyManager;

alarm 45;
for my $transport (qw(tcp http-proxy)) {
for my $mode (qw(expired-fin expired-reset fresh disabled default busy-body accepted-post)) {
  subtest "$transport $mode" => sub {
    my $listener = IO::Socket::INET->new (
      LocalAddr => '127.0.0.1', LocalPort => 0, Listen => 2,
    ) or die $!;
    my $port = $listener->sockport;
    pipe my $control_r, my $control_w or die $!;
    pipe my $ack_r, my $ack_w or die $!;
    pipe my $report_r, my $report_w or die $!;
    my $pid = fork;
    die $! unless defined $pid;
    if (!$pid) {
      close $control_w;
      close $ack_r;
      close $report_r;
      $report_w->autoflush (1);
      my $handle = sub {
        my ($socket, $connection, $length, $no_response) = @_;
        $socket->autoflush (1);
        my $headers = '';
        until ($headers =~ /\r\n\r\n/) {
          sysread ($socket, my $byte, 1) or die 'incomplete headers';
          $headers .= $byte;
        }
        my ($method) = $headers =~ /\A([A-Z]+) /;
        my ($body_length) = $headers =~ /\r\nContent-Length: ([0-9]+)/i;
        my $body = '';
        while (length $body < ($body_length // 0)) {
          sysread ($socket, my $bytes, $body_length - length $body) or die 'incomplete body';
          $body .= $bytes;
        }
        print $report_w "$connection $method $body\n";
        print $socket "HTTP/1.1 200 OK\r\nContent-Length: $length\r\nConnection: keep-alive\r\n\r\n" . ('x' x $length)
            unless $no_response;
      };
      my $ok = eval {
        local $SIG{ALRM} = sub { die 'deadline' };
        alarm 4;
        my $first = $listener->accept or die $!;
        $handle->($first, 1, $mode eq 'busy-body' ? 1024*1024 : 1);
        if ($mode =~ /^expired/) {
          my @ready = IO::Select->new ($first, $control_r)->can_read (3);
          die 'no idle transition' unless @ready;
          my $controlled = grep { fileno $_ == fileno $control_r } @ready;
          if ($controlled) {
            sysread ($control_r, my $signal, 1) or die 'missing signal';
          } else {
            my $n = sysread $first, my $byte, 1;
            die 'expired connection reused' if !defined $n or $n != 0;
          }
          setsockopt $first, SOL_SOCKET, SO_LINGER, pack ('ii', 1, 0)
              if $mode eq 'expired-reset';
          close $first;
          syswrite ($ack_w, 'x') if $controlled;
          my $second = $listener->accept or die $!;
          $handle->($second, 2, 1);
          close $second;
        } else {
          $handle->($first, 1, 1, $mode eq 'accepted-post');
          setsockopt $first, SOL_SOCKET, SO_LINGER, pack ('ii', 1, 0)
              if $mode eq 'accepted-post';
          close $first;
        }
        1;
      };
      print $report_w "SERVER_ERROR\n" unless $ok;
      close $report_w;
      POSIX::_exit ($ok ? 0 : 1);
    }
    close $listener;
    close $control_r;
    close $ack_w;
    close $report_w;
    my $options = $transport eq 'tcp' ? {} : {
      proxy_manager => Web::Transport::ConstProxyManager->new_from_arrayref ([
        {protocol => 'http', host => '127.0.0.1', port => $port},
      ]),
    };
    $options->{max_idle_time} = $mode eq 'disabled' ? 0 : 30 unless $mode eq 'default';
    my $client = Web::Transport::BasicClient->new_from_url (
      Web::URL->parse_string ($transport eq 'tcp' ? "http://127.0.0.1:$port" : 'http://origin.invalid'),
      $options,
    );
    # Advance only the idle-policy clock.  No server deadline or request is changed.
    my $clock = 0;
    $client->{idle_clock} = sub { $clock };
    my $first = $client->request (method => 'GET', path => ['probe'],
        stream => $mode eq 'busy-body')->to_cv->recv;
    is $first->status, 200, 'first response succeeds';
    my $initial_http = $client->{http};
    weaken $initial_http;
    $clock = $mode eq 'fresh' || $mode eq 'accepted-post' ? 10 : 61;
    my $original_write = \&ArrayBuffer::manakai_syswrite;
    my $closed_before_write = 0;
    my ($second, $error, $pending);
    {
      no warnings 'redefine';
      local *ArrayBuffer::manakai_syswrite = sub ($$;$$) {
        if ($mode =~ /^expired/ && !$closed_before_write && defined $initial_http &&
            defined $client->{http} && $client->{http} == $initial_http &&
            defined $_[1] && defined getsockname $_[1] &&
            (defined $_[2] ? $_[2] : $_[0]->byte_length) > 0) {
          $closed_before_write++;
          syswrite ($control_w, 'x');
          sysread ($ack_r, my $ack, 1) or die 'missing close acknowledgement';
          my $check = $initial_http->{info}->{parent}->{read_eof_pending};
          my $deadline = Time::HiRes::time + 1;
          until ($check->()) {
            die 'close not readable' if Time::HiRes::time > $deadline;
            Time::HiRes::sleep (0.001);
          }
        }
        return $original_write->(@_);
      };
      $pending = $client->request (method => 'POST', path => ['probe'], body => 'once');
      if ($mode eq 'busy-body') {
        my $reader = $first->{body_stream}->get_reader ('byob');
        my $received = 0;
        while (1) {
          my $chunk = $reader->read (DataView->new (ArrayBuffer->new (65536)))->to_cv->recv;
          last if $chunk->{done};
          $received += $chunk->{value}->byte_length;
        }
        is $received, 1024*1024, 'the active response is not interrupted by idle expiry';
      }
      eval { $second = $pending->to_cv->recv; 1 } or $error = $@;
    }
    if ($mode eq 'accepted-post') {
      ok $error && $error->is_network_error, 'an error after an accepted POST stays visible';
      ok !defined $second, 'no successful response is fabricated';
    } else {
      is $error, undef, 'one caller POST succeeds without retransmission';
      is $second && $second->status, 200, 'POST receives a successful response';
    }
    is $closed_before_write, 0, 'no new request is written to an expired idle connection';
    $client->close->to_cv->recv;
    close $control_w;
    close $ack_r;
    my @requests = <$report_r>;
    close $report_r;
    waitpid $pid, 0;
    is $?, 0, 'server exits normally';
    my $connection = $mode =~ /^expired/ ? 2 : 1;
    is_deeply \@requests, ["1 GET \n", "$connection POST once\n"],
        'POST is processed exactly once; fresh and active connections stay reusable';
    done_testing;
  };
}
}
done_testing;
