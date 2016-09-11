use strict;
use warnings;
use AnyEvent::Socket;
use Web::Transport::HTTPServerConnection;
use Data::Dumper;

my $host = 0;
my $port = 8522;

$Web::Transport::HTTPServerConnection::ReadTimeout = $ENV{SERVER_READ_TIMEOUT}
    if $ENV{SERVER_READ_TIMEOUT};

my $cb = sub {
  my $self = $_[0];
  my $type = $_[1];
  if ($type eq 'open') {
    my $data = $_[2];
    warn "> Connection opened (Client: $data->{client_ip_addr}:$data->{client_port})\n";
  } elsif ($type eq 'close') {
    warn "> Connection closed\n";
  } elsif ($type eq 'requestheaders') {
    my $req = $_[2];
    warn sprintf "> requestheaders version=%.1f method=%s target=%s\n",
        $req->{version}, $req->{method}, $req->{target};
    for (@{$req->{headers}}) {
      warn ">  + $_->[0]: $_->[1]\n";
    }

    if ($req->{target} =~ m{^/}) {
      #
    } elsif ($req->{target} =~ m{^[A-Za-z][A-Za-z0-9.+-]+://}) {
      #
    } else {
      return $self->_fatal ($req);
    }

    if ($req->{target} eq '/end') {
      $req->send_response_headers
          ({status => 200, status_text => 'OK', headers => []}); # XXX
      $self->{transport}->push_write (\qq{<html>200 Goodbye!\x0D\x0A\x0D\x0A</html>
});
      AE::postpone { exit };
      $req->_response_done;
    } elsif ($self->{write_closed}) {
      #
      $req->_response_done;
    } elsif ($req->{method} eq 'GET' or
             $req->{method} eq 'POST') {
      $req->send_response_headers
          ({status => 404, status_text => 'Not Found', headers => []}, close => 0); # XXX
      $self->{transport}->push_write (\qq{<html>...404 Not Found\x0D\x0A\x0D\x0A</html>
});
      $req->_response_done;
    } elsif ($req->{method} eq 'HEAD') {
      $req->send_response_headers
          ({status => 404, status_text => 'Not Found', headers => []}); # XXX
      $req->_response_done;
    } else {
      $req->send_response_headers
          ({status => 405, status_text => 'Not Allowed', headers => []}); # XXX
      $self->{transport}->push_write (\qq{<html>...405 Not Allowed (@{[$req->{method}]})</html>
});
      $req->_response_done;
    }
  } elsif ($type eq 'data') {
    my $d = $_[2];
    if (length $d > 100) {
      $d = substr $d, 0, 100;
      $d =~ s/([^\x21-\x24\x26-\x7E])/sprintf '%%%02X', ord $1/ge;
      warn "> data |$d|... (length=@{[length $_[2]]})\n";
    } else {
      $d =~ s/([^\x21-\x24\x26-\x7E])/sprintf '%%%02X', ord $1/ge;
      warn "> data |$d| (length=@{[length $_[2]]})\n";
    }
  } elsif ($type eq 'complete') {
    warn "> complete " . join ' ', %{$_[2]}, "\n";
  } else {
    warn "> $type\n";
  }
}; # $cb

my $server = tcp_server $host, $port, sub {
  Web::Transport::HTTPServerConnection->new_from_fh_and_host_and_port_and_cb
      ($_[0], $_[1], $_[2], $cb);
};

AE::cv->recv;
