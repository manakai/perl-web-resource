use strict;
use FindBin;
use lib glob "$FindBin::Bin/../modules/*/lib";
use lib glob "$FindBin::Bin/../t_deps/modules/*/lib";
use lib "$FindBin::Bin/../lib";
use warnings;
use Test::More;
use IO::Socket::INET;
use Socket qw(SOL_SOCKET SO_LINGER);
use Errno qw(EACCES);
use Web::Host;
use Web::Transport::TCPStream;

alarm 15;
for my $reset (0, 1) {
  subtest "idle TCP peer reset=$reset" => sub {
    my $listener = IO::Socket::INET->new (
      LocalAddr => '127.0.0.1', LocalPort => 0, Listen => 1,
    ) or die $!;
    my $socket = IO::Socket::INET->new (
      PeerAddr => '127.0.0.1', PeerPort => $listener->sockport,
    ) or die $!;
    my $peer = $listener->accept or die $!;
    $socket->blocking (0);
    my $stream = Web::Transport::TCPStream->create ({
      fh => $socket, host => Web::Host->parse_string ('127.0.0.1'),
      port => $listener->sockport,
    })->to_cv->recv;
    my $check = $stream->{read_eof_pending};
    ok !$check->(), 'live idle socket is not closed';
    is syswrite ($peer, 'x'), 1, 'peer sends a byte';
    my $readable = '';
    vec ($readable, fileno $socket, 1) = 1;
    is select ($readable, undef, undef, 1), 1, 'data is available';
    ok !$check->(), 'pending data is not a closed connection';
    is sysread ($socket, my $byte, 1), 1, 'peek did not consume the byte';
    is $byte, 'x', 'pending data is unchanged';

    # Block only this event loop so the socket check observes the close first.
    setsockopt $peer, SOL_SOCKET, SO_LINGER, pack ('ii', 1, 0) if $reset;
    close $peer;
    close $listener;
    $readable = '';
    vec ($readable, fileno $socket, 1) = 1;
    is select ($readable, undef, undef, 1), 1, 'close is available before event loop';
    {
      local $! = EACCES;
      ok $check->(), 'already closed peer is detected before send';
      is 0+$!, EACCES, 'checking does not change caller errno';
    }
    my $reader = $stream->{readable}->get_reader ('byob');
    $reader->cancel->catch (sub { })->to_cv->recv;
    my $writer = $stream->{writable}->get_writer;
    $writer->abort->catch (sub { })->to_cv->recv;
    done_testing;
  };
}
done_testing;
