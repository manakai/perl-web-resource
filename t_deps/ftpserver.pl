use strict;
use warnings;
use AnyEvent;
use Promise;

{
  package Server;
  use AnyEvent::Socket;

  sub new ($$$$$) {
    my ($class, $host, $port, $is_data, $cb) = @_;

    warn "Server: $host:$port\n";

    my $self = bless {cb => $cb}, $class;
    $self->{server} = tcp_server $host, $port, sub {
      my ($fh, $client_host, $client_port) = @_;
      warn "Client: $client_host:$client_port\n";

      $self->{buffer} = '';
      $self->{connection} = Connection->new ($fh, sub {
        $self->{buffer} .= $_[0];
        if ($self->{buffer} =~ s/\A(.*?)\x0D\x0A//s) {
          my $line = $1;
          if ($line =~ s/^([A-Za-z]+)//) {
            my $command = $1;
            $command =~ tr/a-z/A-Z/;
            $cb->($self, {command => $command, args => $line});
          } else {
            warn "Unknown line |$line|\n";
          }
        }
      });

      $self->{cb}->($self, {command => 'connect'});

    };
    return $self;
  } # new

  sub response ($$$) {
    my ($self, $code, $status) = @_;
    warn "S: $code $status\x0D\x0A";
    $self->{connection}->send ("$code $status\x0D\x0A");
  }

  sub data_server ($$$) {
    my ($self, $host, $port) = @_;
    my $ok;
    $self->{data_server_promise} = Promise->new (sub { $ok = $_[0] });
    $self->{data_server} = Server->new ($host, $port, 'data', sub {
      my ($self, $args) = @_;
      if ($args->{command} eq 'connect') {
        $ok->($self);
      }
    });
  } # data_server

  sub send_data ($$) {
    my ($self, $data) = @_;
    $self->{data_server_promise}->then (sub {
      my $data_server = $_[0];
      warn "S: ", Connection::hex_dump ($data), "\n";
      $data_server->{connection}->send ($data);
    });
  } # send_data

  sub close_data ($) {
    my $self = shift;
    $self->{data_server_promise}->then (sub {
      my $data_server = $_[0];
      warn "S: close\n";
      $data_server->{connection}->close;
    });
  } # close_data
}

{
  package Connection;
  use Errno qw(EAGAIN EWOULDBLOCK EINTR);
  use AnyEvent::Util qw(WSAEWOULDBLOCK);


sub hex_dump ($) {
  my $s = $_[0];
  my @x;
  for (my $i = 0; $i * 16 < length $s; $i++) {
    my @d = map {
      my $index = $i*16+$_;
      if ($index < length $s) {
        ord substr $s, $index, 1;
      } else {
        undef;
      }
    } 0..15;
    push @x, (join ' ', map { defined $_ ? sprintf '%02X', $_ : '  ' } @d) . '  ' .
             (join '', map { defined $_ ? ((0x20 <= $_ and $_ <= 0x7E) ? pack 'C', $_ : '.') : ' ' } @d);
  }
  return join "\n", @x;
} # hex_dump

  sub new ($$$) {
    my ($class, $fh, $cb) = @_;
    my $self = bless {fh => $fh}, $class;
    $self->{rw} = AE::io $fh, 0, sub {
      my $buffer = '';
      my $l = sysread $fh, $buffer, 128*1024, 0;
      if (defined $l) {
        if ($l > 0) {
          warn "C: ", hex_dump $buffer, "\n";
          $cb->($buffer);
          $buffer = '';
        } else {
          delete $self->{rw};
          warn "C: close\n";
          #$self->_close if $self->{write_closed};
        }
      } elsif ($! != EAGAIN && $! != EINTR && $! != EWOULDBLOCK && $! != WSAEWOULDBLOCK) {
        #my $wc = $self->{write_closed};
        warn "C: close\n";
        warn "S: close\n";
        delete $self->{rw};
        #$self->_close;
      }
    }; # $self->{rw}
    return $self;
  } # new

  sub send ($$) {
    my $self = $_[0];
    syswrite $self->{fh}, $_[1];
  } # send

  sub close ($) {
    shutdown $_[0]->{fh}, 1;
  } # close
}

my $Host = '192.168.11.14';
my $Port = 4691;

my $Responses = {};
while (<>) {
  if (/^(\w+)\s+(\d\S*)\s+(.*?),,(.*?),,(\d+)\s+(.*?)$/) {
    $Responses->{$1} = {code => $2, text => $3, data => $4,
                        code2 => $5, text2 => $6};
  } elsif (/^(\w+)\s+,,(.*?),,(\d+)\s+(.*?)$/) {
    $Responses->{$1} = {data => $2, code2 => $3, text2 => $4};
  } elsif (/^(\w+)\s+(\d\S*)\s+(.*?),,(.*?)$/) {
    $Responses->{$1} = {code => $2, text => $3, data => $4};
  } elsif (/^(\w+)\s+,,(.*?)$/) {
    $Responses->{$1} = {data => $2};
  } elsif (/^(\w+)\s+(\d\S*)\s+(.*)$/) {
    $Responses->{$1} = {code => $2, text => $3};
  } elsif (/\S/) {
    die "Bad input |$_|";
  }
}

my $server = Server->new ($Host, $Port, (not 'data'), sub {
  my ($self, $args) = @_;
  my $def = $Responses->{$args->{command}};
  if (defined $def) {
    if (defined $def->{code}) {
      $self->response ($def->{code}, $def->{text});
    }
    if (defined $def->{data}) {
      $self->send_data ($def->{data});
      $self->close_data;
    }
    if (defined $def->{code2}) {
      $self->response ($def->{code2}, $def->{text2});
    }
  } elsif ($args->{command} eq 'PASV') {
    my $host = $Host;
    my $port = 1000 + int rand 10000;
    $self->data_server ($host, $port);
    $self->response (227, sprintf "(%d,%d,%d,%d,%d,%d)",
                         (split /\./, $host), int ($port / 256), $port % 256);
  } else {
    warn "Unknown command |$args->{command}|\n";
  }
});

my $cv = AE::cv;
$cv->recv;
