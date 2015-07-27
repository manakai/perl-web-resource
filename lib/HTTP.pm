package HTTP;
use strict;
use warnings;
use AnyEvent;
use AnyEvent::Handle;
use AnyEvent::Socket;
use Promise;

sub new_from_host_and_port ($$$) {
  return bless {host => $_[1], port => $_[2], state => 'initial',
                next_response_id => 1}, $_[0];
} # new_from_host_and_port

sub connect ($) {
  my $self = $_[0];
  return Promise->new (sub {
    my ($ok, $ng) = @_;
    tcp_connect $self->{host}, $self->{port}, sub {
      my $fh = shift or return $ng->($!);
      $self->{handle} = AnyEvent::Handle->new
          (fh => $fh,
           on_read => sub {
             my ($handle) = @_;
             if ($self->{state} eq 'before response') {
               if ($handle->{rbuf} =~ s/^.{0,4}[Hh][Tt][Tt][Pp]//s) {
                 ## HTTP/1.0 or HTTP/1.1
                 $self->{state} = 'before response 1';
               } elsif (8 <= length $handle->{rbuf}) {
                 $self->onresponsestart->({
                   response_id => $self->{current_response_id},
                   status => 200,
                   version => '0.9',
                   headers => [],
                 });
                 $self->{state} = 'response body';
               }
             } elsif ($self->{state} eq 'before response 1') {
               if (2**18-1 < length $handle->{rbuf}) {
                 $self->onresponsestart->({
                   response_id => $self->{current_response_id},
                   network_error => 1,
                   error => "Header too large",
                 });
               } elsif ($handle->{rbuf} =~ s/^(.*?)\x0D?\x0A\x0D?\x0A//s) {
                 my $headers = [split /\x0D?\x0A/, $1, -1]; # XXX report CR
                 my $start_line = shift @$headers;
warn "<<$start_line>>";
                 my $res = {response_id => $self->{current_response_id},
                            status => 200,
                            version => '1.0',
                            headers => [],
                            start_line => $start_line};
                 if ($start_line =~ s{\A/([0-9]+)\.([0-9]+)[\x09-\x0D\x20]*}{}s) {
                   my $major = 0+$1;
                   my $minor = 0+$2;
                   if ($major > 1 or ($major == 1 and $minor > 0)) {
                     $res->{version} = '1.1';
                   }
                   if ($start_line =~ s/\A([0-9]{3})[\x09-\x0D\x20]*//) {
                     $res->{status} = 0+$1;
                     $res->{reason_phrase} = $start_line;
                   }
                 } elsif ($start_line =~ s{\A[\x090\x0D\x20]+}{}) {
                   if ($start_line =~ s/\A([0-9]{3})[\x09-\x0D\x20]*//) {
                     $res->{status} = 0+$1;
                     $res->{reason_phrase} = $start_line;
                   }
                 }
                 for (@$headers) {
                   if (s/\A([^:]+)://) {
                     my $name = $1;
                     my $value = $_;
                     push @{$res->{headers}}, [$name, $value];
                   } elsif (@{$res->{headers}} and s/\A[\x09\x0A\x0D\x20]+//) {
                     $res->{headers}->[-1]->[1] .= ' ' . $_;
                   } else {
                     # XXX report error
                   }
                 }
                 for (@{$res->{headers}}) {
                   $_->[0] =~ s/[\x09\x0A\x0D\x20]+\z//;
                   $_->[1] =~ s/\A[\x09\x0A\x0D\x20]+//;
                   $_->[1] =~ s/[\x09\x0A\x0D\x20]+\z//;
                 }
                 $self->onresponsestart->($res);
                 $self->{state} = 'response body';
               }
             } elsif ($self->{state} eq 'before response body') {
               $self->onresponsestart->({
                 status => 200,
                 response_id => $self->{current_response_id},
                 version => '0.9',
                 headers => [],
               });
               $self->{state} = 'response body';
             }
             if ($self->{state} eq 'response body') {
               $self->ondata->($self->{current_response_id}, $handle->{rbuf});
               $handle->{rbuf} = '';
             }
           },
           on_error => sub {
             my ($hdl, $fatal, $msg) = @_;
             AE::log error => $msg;
             # XXX
             $self->{handle}->destroy;
             delete $self->{handle};
             $self->onclose->($msg);
           },
           on_eof => sub {
             my ($handle) = @_;
             if ($self->{state} eq 'before response') {
               if (length $self->{handle}->{rbuf}) {
                 $self->onresponsestart->({
                   response_id => $self->{current_response_id},
                   version => '0.9',
                   status => 200,
                   headers => [],
                 });
                 $self->{state} = 'response body';
               } else {
                 $self->onresponsestart->({
                   response_id => $self->{current_response_id},
                   network_error => 1,
                   error => "Connection closed",
                 });
               }
             } elsif ($self->{state} eq 'before response body') {
               unless (length $self->{handle}->{rbuf}) {
                 $self->onresponsestart->({
                   response_id => $self->{current_response_id},
                   network_error => 1,
                   error => "Connection closed",
                 });
               }
             }
             delete $self->{handle};
             $self->onclose->(undef);
           });
      $ok->();
    };
  });
} # connect

sub send_request ($$) {
  my ($self, $req) = @_;
  unless (defined $self->{handle}) {
    return Promise->reject ("Not connected");
  }
  my $version = $req->{version} // '';
  if ($version eq '1.0') {
    unless ($self->{state} eq 'initial') {
      return Promise->reject ("Can't use this connection: |$self->{state}|");
    }
    my $method = $req->{method} // '';
    if (not length $method or $method =~ /[\x0D\x0A\x09\x20]/) {
      return Promise->reject ("Bad |method|: |$method|");
    }
    my $url = $req->{url};
    if (not defined $url or $url =~ /[\x0D\x0A]/ or
        $url =~ /\A[\x0D\x0A\x09\x20]/ or
        $url =~ /[\x0D\x0A\x09\x20]\z/) {
      return Promise->reject ("Bad |url|: |$url|");
    }
    $self->{state} = 'before response';
    $self->{current_response_id} = $self->{next_response_id}++;
    $self->{handle}->push_write ("$method $url HTTP/1.0\x0D\x0A\x0D\x0A");
    return Promise->resolve;
  } elsif ($version eq '0.9') {
    unless ($self->{state} eq 'initial') {
      return Promise->reject ("Can't use this connection: |$self->{state}|");
    }
    my $method = $req->{method} // '';
    if (not $method eq 'GET') {
      return Promise->reject ("Bad |method|: |$method|");
    }
    my $url = $req->{url};
    if (not defined $url or $url =~ /[\x0D\x0A]/ or
        $url =~ /\A[\x0D\x0A\x09\x20]/ or
        $url =~ /[\x0D\x0A\x09\x20]\z/) {
      return Promise->reject ("Bad |url|: |$url|");
    }
    $self->{state} = 'before response body';
    $self->{current_response_id} = $self->{next_response_id}++;
    $self->{handle}->push_write ("$method $url\x0D\x0A");
    return Promise->resolve;
  } else {
    return Promise->reject ("Bad |version|: |$version|");
  }
} # send_request

sub onresponsestart ($;$) {
  if (@_ > 1) {
    $_[0]->{onresponsestart} = $_[1];
  }
  return $_[0]->{onresponsestart} ||= sub { };
} # onresponsestart

sub ondata ($;$) {
  if (@_ > 1) {
    $_[0]->{ondata} = $_[1];
  }
  return $_[0]->{ondata} ||= sub { };
} # ondata

sub onclose ($;$) {
  if (@_ > 1) {
    $_[0]->{onclose} = $_[1];
  }
  return $_[0]->{onclose} ||= sub { };
} # ondata

1;
