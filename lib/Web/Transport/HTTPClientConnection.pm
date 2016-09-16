package Web::Transport::HTTPClientConnection;
use strict;
use warnings;
our $VERSION = '1.0';
use Web::Transport::HTTPStream;
push our @ISA, qw(Web::Transport::HTTPStream);
use Carp qw(croak);
use Errno;
use MIME::Base64 qw(encode_base64);
use Digest::SHA qw(sha1);
use Errno qw(ECONNRESET);
use AnyEvent;
use AnyEvent::Socket;
use Promise;

use constant DEBUG => $ENV{WEBUA_DEBUG} || 0;

BEGIN {
  *_e4d = \&Web::Transport::HTTPStream::_e4d;
  *_e4d_t = \&Web::Transport::HTTPStream::_e4d_t;
}

sub new ($%) {
  my $self = bless {id => '',
                    req_id => 0,
                    rbuf => \(my $x = '')}, shift;
  $self->{args} = {@_};
  return $self;
} # new

sub id ($) {
  if (defined $_[0]->{args}) {
    return $_[0]->{args}->{transport}->id;
  }
  return $_[0]->{id};
} # id

sub request_id ($) {
  if (defined $_[0]->{request}) {
    return $_[0]->id . '.' . $_[0]->{req_id};
  } else {
    return undef;
  }
} # request_id

sub type ($) { return 'HTTP' }
sub layered_type ($) {
  if (defined $_[0]->{args}) {
    return $_[0]->type . '/' . $_[0]->{args}->{transport}->layered_type;
  }
  return $_[0]->type . '/' . $_[0]->{transport}->layered_type;
} # layered_type

sub transport ($) { $_[0]->{transport} }

sub _process_rbuf ($$;%) {
  my ($self, $ref, %args) = @_;
  HEADER: {
  if ($self->{state} eq 'before response') {
    if ($$ref =~ s/^.{0,4}[Hh][Tt][Tt][Pp]//s) {
      $self->{state} = 'before response header';
      $self->{response_received} = 1;
    } elsif (8 <= length $$ref) {
      $self->{response_received} = 1;
      if ($self->{request}->{method} eq 'PUT' or
          $self->{request}->{method} eq 'CONNECT') {
        $self->{no_new_request} = 1;
        $self->{request_state} = 'sent';
        $self->{exit} = {failed => 1,
                         message => "HTTP/0.9 response to non-GET request"};
        $self->_next;
        return;
      } else {
        $self->_ev ('headers', $self->{response});
        $self->_ev ('datastart', {});
        $self->{state} = 'response body';
        delete $self->{unread_length};
      }
    }
  }
  if ($self->{state} eq 'before response header') {
    if (2**18-1 < length $$ref) {
      $self->{no_new_request} = 1;
      $self->{request_state} = 'sent';
      $self->{exit} = {failed => 1,
                       message => "Header section too large"};
      $self->_next;
      return;
    } elsif ($$ref =~ s/^(.*?)\x0A\x0D?\x0A//s or
             ($args{eof} and $$ref =~ s/\A(.*)\z//s and
              $self->{response}->{incomplete} = 1)) {
      my $headers = [split /[\x0D\x0A]+/, $1, -1];
      my $start_line = shift @$headers;
      $start_line = '' unless defined $start_line;
      my $res = $self->{response};
      $res->{version} = '1.0';
      if ($start_line =~ s{\A/}{}) {
        if ($start_line =~ s{\A([0-9]+)}{}) {
          my $major = $1;
          $major = 0 if $major =~ /^0/;
          if ($start_line =~ s{\A\.}{}) {
            if ($start_line =~ s{\A([0-9]+)}{}) {
              my $n = 0+"$major.$1";
              $res->{version} = '1.1' if $n >= 1.1;
            }
          }
        }
        $start_line =~ s{\A\x20*}{}s;
        if ($start_line =~ s/\A0*?([0-9]+)//) {
          $res->{status} = 0+$1;
          $res->{status} = 2**31-1 if $res->{status} > 2**31-1;
          if ($start_line =~ s/\A\x20+//) {
            $res->{reason} = $start_line;
          } else {
            $res->{reason} = '';
          }
        }
      } elsif ($start_line =~ s{\A\x20+}{}) {
        if ($start_line =~ s/\A0*?([0-9]+)//) {
          $res->{status} = 0+$1;
          $res->{status} = 2**31-1 if $res->{status} > 2**31-1;
          if ($start_line =~ s/\A\x20//) {
            $res->{reason} = $start_line;
          } else {
            $res->{reason} = '';
          }
        }
      }

      my $last_header = undef;
      for (@$headers) {
        if (s/^[\x20\x09]+//) {
          if (defined $last_header) {
            $last_header->[1] .= ' ' . $_;
          }
        } elsif (s/\A([^:]+)://) {
          push @{$res->{headers}}, $last_header = [$1, $_];
        } else {
          $last_header = undef;
          # XXX report error
        }
      }
      my %length;
      my $has_broken_length = 0;
      my $te = '';
      for (@{$res->{headers}}) {
        $_->[0] =~ s/[\x09\x20]+\z//;
        $_->[1] =~ s/\A[\x09\x20]+//;
        $_->[1] =~ s/[\x09\x20]+\z//;
        $_->[2] = $_->[0];
        $_->[2] =~ tr/A-Z/a-z/; ## ASCII case-insensitive
        if ($_->[2] eq 'transfer-encoding') {
          $te .= ',' . $_->[1];
        } elsif ($_->[2] eq 'content-length') {
          for (split /[\x09\x20]*,[\x09\x20]*/, $_->[1]) {
            if (/\A[0-9]+\z/) {
              $length{$_}++;
            } else {
              $has_broken_length = 1;
            }
          }
        }
      }
      $te =~ tr/A-Z/a-z/; ## ASCII case-insensitive.
      my $chunked = !!grep { $_ eq 'chunked' } split /[\x09\x20]*,[\x09\x20]*/, $te;
      delete $self->{unread_length};
      if ($chunked and $self->{response}->{version} eq '1.1') {
        $has_broken_length = 0;
        %length = ();
      } else {
        $chunked = 0;
      }
      if (($has_broken_length and keys %length) or 1 < keys %length) {
        $self->{no_new_request} = 1;
        $self->{request_state} = 'sent';
        $self->{exit} = {failed => 1,
                         message => "Inconsistent content-length values"};
        $self->_next;
        return;
      } elsif (1 == keys %length) {
        my $length = each %length;
        $length =~ s/\A0+//;
        $length ||= 0;
        if ($length eq 0+$length) { # overflow check
          $self->{unread_length} = $res->{content_length} = 0+$length;
        } else {
          $self->{no_new_request} = 1;
          $self->{request_state} = 'sent';
          $self->{exit} = {failed => 1,
                           message => "Inconsistent content-length values"};
          $self->_next;
          return;
        }
      }

      if ($res->{status} == 200 and
          $self->{request}->{method} eq 'CONNECT') {
        $self->_ev ('headers', $res);
        $self->_ev ('datastart', {});
        $self->{no_new_request} = 1;
        $self->{state} = 'tunnel';
      } elsif (defined $self->{ws_state} and
               $self->{ws_state} eq 'CONNECTING' and
               $res->{status} == 101) {
        my $failed = 0;
        {
          my $ug = '';
          my $con = '';
          my $accept = '';
          my $proto;
          my $exts = '';
          for (@{$res->{headers}}) {
            if ($_->[2] eq 'upgrade') {
              $ug .= ',' . $_->[1];
            } elsif ($_->[2] eq 'connection') {
              $con .= ',' . $_->[1];
            } elsif ($_->[2] eq 'sec-websocket-accept') {
              $accept .= ',' if not defined $accept;
              $accept .= $_->[1];
            } elsif ($_->[2] eq 'sec-websocket-protocol') {
              $proto .= ',' if defined $proto;
              $proto .= $_->[1];
            } elsif ($_->[2] eq 'sec-websocket-extensions') {
              $exts .= ',' . $_->[2];
            }
          }
          $ug =~ tr/A-Z/a-z/;
          do { $failed = 1; last } unless
              grep { $_ eq 'websocket' } map {
                s/\A[\x09\x0A\x0D\x20]+//; s/[\x09\x0A\x0D\x20]+\z//; $_;
              } split /,/, $ug;
          $con =~ tr/A-Z/a-z/;
          do { $failed = 1; last } unless
              grep { $_ eq 'upgrade' } map {
                s/\A[\x09\x0A\x0D\x20]+//; s/[\x09\x0A\x0D\x20]+\z//; $_;
              } split /,/, $con;
          do { $failed = 1; last } unless
              $accept eq encode_base64 sha1 ($self->{ws_key} . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'), '';
          if (defined $proto) {
            do { $failed = 1; last }
                if not grep { $_ eq $proto } @{$self->{ws_protos}};
          } else {
            do { $failed = 1; last } if @{$self->{ws_protos}};
          }
          do { $failed = 1; last }
              if grep { length $_ } split /,/, $exts;
        }
        if ($failed) {
          $self->_ev ('headers', $res);
          $self->{exit} = {ws => 1, failed => 1, status => 1006, reason => ''};
          $self->{no_new_request} = 1;
          $self->{request_state} = 'sent';
          $self->_next;
          return;
        } else {
          $self->{ws_state} = 'OPEN';
          $self->_ev ('headers', $res, 1);
          $self->{no_new_request} = 1;
          $self->{state} = 'before ws frame';
          if (defined $self->{pending_frame}) {
            $self->{ws_state} = 'CLOSING';
            $self->{transport}->push_write (\($self->{pending_frame}));
            $self->_ws_debug ('S', @{$self->{pending_frame_info}}) if DEBUG;
            $self->{timer} = AE::timer 20, 0, sub {
              warn "$self->{request}->{id}: WS timeout (20)\n" if DEBUG;
              delete $self->{timer};
              $self->_next;
            };
          }
        }
      } elsif (100 <= $res->{status} and $res->{status} <= 199) {
        if ($self->{request}->{method} eq 'CONNECT' or
            (defined $self->{ws_state} and
             $self->{ws_state} eq 'CONNECTING')) {
          $self->{no_new_request} = 1;
          $self->{request_state} = 'sent';
          $self->{exit} = {failed => 1,
                           message => "1xx response to CONNECT or WS"};
          $self->_next;
          return;
        } else {
          #push @{$res->{'1xxes'} ||= []}, {
          #  version => $res->{version},
          #  status => $res->{status},
          #  reason => $res->{reason},
          #  headers => $res->{headers},
          #};
          $res->{version} = '0.9';
          $res->{status} = 200;
          $res->{reason} = 'OK';
          $res->{headers} = [];
          $self->{state} = 'before response';
          redo HEADER;
        }
      } elsif ($res->{status} == 204 or
               $res->{status} == 205 or
               $res->{status} == 304 or
               $self->{request}->{method} eq 'HEAD') {
        $self->_ev ('headers', $res);
        $self->_ev ('datastart', {});
        $self->{unread_length} = 0;
        $self->{state} = 'response body';
      } else {
        $self->_ev ('headers', $res);
        $self->_ev ('datastart', {});
        if ($chunked) {
          $self->{state} = 'before response chunk';
        } else {
          $self->{state} = 'response body';
        }
      }
    }
  }
  } # HEADER
  if ($self->{state} eq 'response body') {
    if (defined $self->{unread_length}) {
      if ($self->{unread_length} >= (my $len = length $$ref)) {
        if ($len) {
          $self->_ev ('data', $$ref);
          $$ref = '';
          $self->{unread_length} -= $len;
        }
      } elsif ($self->{unread_length} > 0) {
        $self->_ev ('data', substr $$ref, 0, $self->{unread_length});
        substr ($$ref, 0, $self->{unread_length}) = '';
        $self->{unread_length} = 0;
      }
      if ($self->{unread_length} <= 0) {
        $self->_ev ('dataend', {});

        my $connection = '';
        my $keep_alive = $self->{response}->{version} eq '1.1';
        for (@{$self->{response}->{headers} || []}) {
          if ($_->[2] eq 'connection') {
            $connection .= ',' . $_->[1];
          }
        }
        $connection =~ tr/A-Z/a-z/; ## ASCII case-insensitive
        for (split /[\x09\x20]*,[\x09\x20]*/, $connection) {
          if ($_ eq 'close') {
            $self->{no_new_request} = 1;
            last;
          } elsif ($_ eq 'keep-alive') {
            $keep_alive = 1;
          }
        }
        $self->{no_new_request} = 1 unless $keep_alive;

        $self->{exit} = {};
        $self->_next;
      }
    } else {
      $self->_ev ('data', $$ref)
          if length $$ref;
      $$ref = '';
    }
  }
  CHUNK: {
  if ($self->{state} eq 'before response chunk') {
    if ($$ref =~ /^[0-9A-Fa-f]/) {
      $self->{state} = 'response chunk size';
    } elsif (length $$ref) {
      $self->{response}->{incomplete} = 1;
      $self->{no_new_request} = 1;
      $self->{request_state} = 'sent';
      $self->_ev ('dataend', {});
      $self->{exit} = {};
      $self->_next;
      return;
    }
  }
  if ($self->{state} eq 'response chunk size') {
    if ($$ref =~ s/^([0-9A-Fa-f]+)(?![0-9A-Fa-f])//) {
      my $h = $1;
      $h =~ tr/A-F/a-f/;
      $h =~ s/^0+//;
      $h ||= 0;
      my $n = hex $h;
      if (not $h eq sprintf '%x', $n) { # overflow
        $self->{response}->{incomplete} = 1;
        $self->{no_new_request} = 1;
        $self->{request_state} = 'sent';
        $self->_ev ('dataend', {});
        $self->{exit} = {};
        $self->_next;
        return;
      }
      if ($n == 0) {
        $self->_ev ('dataend', {});
        $self->{state} = 'before response trailer';
      } else {
        $self->{unread_length} = $n;
        if ($$ref =~ s/^\x0A//) {
          $self->{state} = 'response chunk data';
        } else {
          $self->{state} = 'response chunk extension';
        }
      }
    }
  }
  if ($self->{state} eq 'response chunk extension') {
    $$ref =~ s/^[^\x0A]+//;
    if ($$ref =~ s/^\x0A//) {
      $self->{state} = 'response chunk data';
    }
  }
  if ($self->{state} eq 'response chunk data') {
    if ($self->{unread_length} > 0) {
      my $len = length $$ref;
      if ($len <= 0) {
        #
      } elsif ($self->{unread_length} >= $len) {
        $self->_ev ('data', $$ref);
        $$ref = '';
        $self->{unread_length} -= $len;
      } else {
        $self->_ev ('data', substr $$ref, 0, $self->{unread_length});
        substr ($$ref, 0, $self->{unread_length}) = '';
        $self->{unread_length} = 0;
      }
    }
    if ($self->{unread_length} <= 0) {
      if ($$ref =~ s/^\x0D?\x0A//) {
        delete $self->{unread_length};
        $self->{state} = 'before response chunk';
        redo CHUNK;
      } elsif ($$ref =~ /^(?:\x0D[^\x0A]|[^\x0D\x0A])/) {
        delete $self->{unread_length};
        $self->{response}->{incomplete} = 1;
        $self->{no_new_request} = 1;
        $self->{request_state} = 'sent';
        $self->_ev ('dataend', {});
        $self->{exit} = {};
        $self->_next;
        return;
      }
    }
  }
  } # CHUNK
  if ($self->{state} eq 'before response trailer') {
    if (2**18-1 < length $$ref) {
      $self->{no_new_request} = 1;
      $self->{request_state} = 'sent';
      $self->{exit} = {};
      $self->_next;
      return;
    } elsif ($$ref =~ s/^(.*?)\x0A\x0D?\x0A//s) {
      my $connection = '';
      for (@{$self->{response}->{headers} || []}) {
        if ($_->[2] eq 'connection') {
          $connection .= ',' . $_->[1];
        }
      }
      $connection =~ tr/A-Z/a-z/; ## ASCII case-insensitive
      for (split /[\x09\x20]*,[\x09\x20]*/, $connection) {
        if ($_ eq 'close') {
          $self->{no_new_request} = 1;
          last;
        }
      }
      $self->{exit} = {};
      $self->_next;
      return;
    }
  }
  if ($self->{state} eq 'before ws frame' or
      $self->{state} eq 'ws data' or
      $self->{state} eq 'ws terminating') {
    return $self->_ws_received ($ref, %args);
  }
  if ($self->{state} eq 'tunnel' or $self->{state} eq 'tunnel receiving') {
    $self->_ev ('data', $$ref)
        if length $$ref;
    $$ref = '';
  }
  if ($self->{state} eq 'waiting' or
      $self->{state} eq 'sending' or
      $self->{state} eq 'tunnel sending' or
      $self->{state} eq 'stopped') {
    $$ref = '';
  }
} # _process_rbuf

sub _process_rbuf_eof ($$;%) {
  my ($self, $ref, %args) = @_;

  if ($self->{state} eq 'before response') {
    if (length $$ref) {
      if ($self->{request}->{method} eq 'PUT' or
          $self->{request}->{method} eq 'CONNECT') {
        $self->{exit} = {failed => 1,
                         message => "HTTP/0.9 response to non-GET request"};
      } else {
        $self->_ev ('headers', $self->{response});
        $self->_ev ('datastart', {});
        $self->_ev ('data', $$ref);
        $self->_ev ('dataend', {});
        $self->{exit} = {};
        $self->{response}->{incomplete} = 1 if $args{abort};
      }
      $$ref = '';
    } else { # empty
      $self->{exit} = {failed => 1,
                       message => "Connection closed without response",
                       errno => $args{errno},
                       can_retry => !$args{abort} && !$self->{response_received}};
    }
  } elsif ($self->{state} eq 'response body') {
    if (defined $self->{unread_length} and $self->{unread_length} > 0) {
      $self->{response}->{incomplete} = 1;
      $self->{request_state} = 'sent';
      $self->_ev ('dataend', {});
      if ($self->{response}->{version} eq '1.1') {
        $self->{exit} = {failed => 1,
                         message => "Connection truncated",
                         errno => $args{errno}};
      } else {
        $self->{exit} = {};
      }
    } else {
      if ($args{abort}) {
        if (defined $self->{unread_length}) { #$self->{unread_length} == 0
          $self->{request_state} = 'sent';
        } else {
          $self->{response}->{incomplete} = 1;
        }
      }
      $self->_ev ('dataend', {});
      $self->{exit} = {};
    }
  } elsif ({
    'before response chunk' => 1,
    'response chunk size' => 1,
    'response chunk extension' => 1,
    'response chunk data' => 1,
  }->{$self->{state}}) {
    $self->{response}->{incomplete} = 1;
    $self->{request_state} = 'sent';
    $self->_ev ('dataend', {});
    $self->{exit} = {};
  } elsif ($self->{state} eq 'before response trailer') {
    $self->{request_state} = 'sent';
    $self->{exit} = {};
  } elsif ($self->{state} eq 'tunnel') {
    $self->_ev ('dataend');
    unless ($args{abort}) {
      $self->{no_new_request} = 1;
      $self->{state} = 'tunnel sending';
      return;
    }
  } elsif ($self->{state} eq 'tunnel receiving') {
    $self->_ev ('dataend');
    $self->{exit} = {failed => $args{abort}};
  } elsif ($self->{state} eq 'before response header') {
    $self->{exit} = {failed => 1,
                     message => "Connection closed within response headers",
                     errno => $args{errno}};
  } elsif ($self->{state} eq 'before ws frame' or
           $self->{state} eq 'ws data' or
           $self->{state} eq 'ws terminating') {
    return $self->_ws_received_eof ($ref, %args);
  }

  $self->{no_new_request} = 1;
  $self->{request_state} = 'sent';
  $self->_next;
} # _process_rbuf_eof

sub _next ($) {
  my $self = $_[0];
  return if $self->{state} eq 'stopped';

  delete $self->{timer};
  if (defined $self->{request_state} and
      ($self->{request_state} eq 'sending headers' or
       $self->{request_state} eq 'sending body')) {
    $self->{state} = 'sending';
  } else {
    if (defined $self->{request} and
        defined $self->{request_state} and
        $self->{request_state} eq 'sent') {
      $self->_ev ('complete', $self->{exit});
    }
    my $id = defined $self->{request} ? $self->{request}->{id}.': ' : '';
    delete $self->{request};
    delete $self->{response};
    delete $self->{request_state};
    delete $self->{to_be_sent_length};
    if ($self->{no_new_request}) {
      my $transport = $self->{transport};
      $transport->push_shutdown unless $transport->write_to_be_closed;
      $self->{timer} = AE::timer 1, 0, sub {
        $transport->abort;
      };
      $self->{state} = 'stopped';
    } else {
      $self->{state} = 'waiting';
      $self->{response_received} = 0;
    }
  }
} # _next

sub debug_handshake_done ($$$) {
  my ($self, $ok, $info) = @_;
  no warnings 'uninitialized';

  my $id = $self->{transport}->id;
  warn "$id: Connection established @{[scalar gmtime]}\n" if $ok;

  if ($self->{transport}->type eq 'TCP') {
    my $data = $info->{transport_data};
    warn "$id: + Local: $data->{local_host}:$data->{local_port}\n";
  }

  if ($self->{transport}->type eq 'TLS') {
    my $data = $info->{transport_data};

    if ($data->{parent_transport_type} eq 'TCP') {
      my $data = $data->{parent_transport_data};
      warn "$id: + TCP Local: $data->{local_host}:$data->{local_port}\n";
    }

    if (defined $data->{tls_protocol}) {
      my $ver = $data->{tls_protocol} == 0x0301 ? '1.0' :
                $data->{tls_protocol} == 0x0302 ? '1.1' :
                $data->{tls_protocol} == 0x0303 ? '1.2' :
                $data->{tls_protocol} == 0x0304 ? '1.3' :
                sprintf '0x%04X', $data->{tls_protocol};
      warn "$id: + TLS version: $ver\n";
    }
    if (defined $data->{tls_cipher}) {
      warn "$id: + Cipher suite: $data->{tls_cipher} ($data->{tls_cipher_usekeysize})\n";
    }
    warn "$id: + Resumed session\n" if $data->{tls_session_resumed};
    my $i = 0;
    for (@{$data->{tls_cert_chain} or []}) {
      if (defined $_) {
        warn "$id: + #$i: @{[$_->debug_info]}\n";
      } else {
        warn "$id: + #$i: ?\n";
      }
      $i++;
    }
    if (defined (my $result = $data->{stapling_result})) {
      if ($result->{failed}) {
        warn "$id: + OCSP stapling: NG - $result->{message}\n";
      } else {
        warn "$id: + OCSP stapling: OK\n";
      }
      if (defined (my $res = $result->{response})) {
        warn "$id: +   Status=$res->{response_status} Produced=$res->{produced}\n";
        for my $r (values %{$res->{responses} or {}}) {
          warn "$id: +   - Status=$r->{cert_status} Revocation=$r->{revocation_time} ThisUpdate=$r->{this_update} NextUpdate=$r->{next_update}\n";
        }
      }
    } elsif (defined $data->{tls_protocol}) {
      warn "$id: + OCSP stapling: N/A\n";
    }
  } # TLS

  if (not $ok) {
    my $msg = (defined $info && ref $info eq 'HASH' &&
               defined $info->{exit} && ref $info->{exit} eq 'HASH' &&
               defined $info->{exit}->{message})
                  ? $info->{exit}->{message} :
              (defined $info && ref $info eq 'HASH' && $info->{failed} &&
               defined $info->{message})
                  ? $info->{message} :
              (defined $info && ref $info eq 'HASH' &&
               defined $info->{response} &&
               defined $info->{response}->{status})
                  ? $info->{response}->{status}
                  : $info;
    warn "$id: Connection failed ($msg) @{[scalar gmtime]}\n";
  }
} # debug_handshake_done

sub connect ($) {
  my ($self) = @_;
  croak "Bad state" if not defined $self->{args};
  my $args = delete $self->{args};
  $self->{transport} = $args->{transport};
  $self->{id} = $self->{transport}->id;
  $self->{state} = 'initial';
  $self->{response_received} = 1;

  my $onclosed;
  my $closed = Promise->new (sub { $onclosed = $_[0] });
  $self->{closed} = $closed;

  if (DEBUG) {
    my $id = $self->{transport}->id;
    warn "$id: Connect (@{[$self->{transport}->layered_type]})... @{[scalar gmtime]}\n";
  }

  my $p = $self->{transport}->start (sub {
    my ($transport, $type) = @_;
    if ($type eq 'readdata') {
      ${$self->{rbuf}} .= ${$_[2]};
      $self->_process_rbuf ($self->{rbuf});
    } elsif ($type eq 'readeof') {
      my $data = $_[2];
      if (DEBUG) {
        my $id = $self->{transport}->id;
        if (defined $data->{message}) {
          warn "$id: R: EOF ($data->{message})\n";
        } else {
          warn "$id: R: EOF\n";
        }
      }

      if ($data->{failed}) {
        if (defined $data->{errno} and $data->{errno} == ECONNRESET) {
          $self->{no_new_request} = 1;
          $self->{request_state} = 'sent';
          $self->{exit} = {failed => 1, reset => 1};
          $self->_next;
        } else {
          $self->_process_rbuf ($self->{rbuf}, eof => 1);
          $self->_process_rbuf_eof
              ($self->{rbuf}, abort => $data->{failed}, errno => $data->{errno});
        }
        $transport->abort;
      } else {
        $self->_process_rbuf ($self->{rbuf}, eof => 1);
        $self->_process_rbuf_eof ($self->{rbuf});
        unless ($self->{state} eq 'tunnel sending') {
          $transport->push_shutdown unless $transport->write_to_be_closed;
        }
      }
    } elsif ($type eq 'writeeof') {
      my $data = $_[2];
      if (DEBUG) {
        my $id = $self->{transport}->id;
        if (defined $data->{message}) {
          warn "$id: S: EOF ($data->{message})\n";
        } else {
          warn "$id: S: EOF\n";
        }
      }

      if ($self->{state} eq 'tunnel sending') {
        $self->_ev ('complete', {});
      }
    } elsif ($type eq 'close') {
      if (DEBUG) {
        my $id = $self->{transport}->id;
        warn "$id: Connection closed @{[scalar gmtime]}\n";
      }
      $onclosed->();
    }
  })->then (sub {
    debug_handshake_done $self, 1, {transport_data => $_[0]} if DEBUG;
  }, sub {
    my $error = $_[0];
    debug_handshake_done $self, 0, $error if DEBUG;
    $self->{transport}->abort;
    $onclosed->();
    die $error;
  });
} # connect

sub is_active ($) {
  return defined $_[0]->{state} && !$_[0]->{no_new_request};
} # is_active

sub send_request_headers ($$;%) {
  my ($self, $req, %args) = @_;
  my $method = defined $req->{method} ? $req->{method} : '';
  if (not length $method or $method =~ /[\x0D\x0A\x09\x20]/) {
    croak "Bad |method|: |$method|";
  }
  my $url = $req->{target};
  if (not defined $url or
      not length $url or
      $url =~ /[\x0D\x0A]/ or
      $url =~ /\A[\x09\x20]/ or
      $url =~ /[\x09\x20]\z/) {
    croak "Bad |target|: |$url|";
  }
  $self->{to_be_sent_length} = 0;
  for (@{$req->{headers} or []}) {
    croak "Bad header name |$_->[0]|"
        unless $_->[0] =~ /\A[!\x23-'*-+\x2D-.0-9A-Z\x5E-z|~]+\z/;
    croak "Bad header value |$_->[1]|"
        unless $_->[1] =~ /\A[\x00-\x09\x0B\x0C\x0E-\xFF]*\z/;
    my $n = $_->[0];
    $n =~ tr/A-Z/a-z/; ## ASCII case-insensitive.
    if ($n eq 'content-length') {
      $self->{to_be_sent_length} = $_->[1]; # XXX
      # XXX throw if multiple length?
    }
  }
  # XXX transfer-encoding
  # XXX croak if WS protocols is bad
  # XXX utf8 flag
  # XXX header size

  if (not defined $self->{state}) {
    return Promise->reject ("Connection has not been established");
  } elsif ($self->{no_new_request}) {
    return Promise->reject ("Connection is no longer in active");
  } elsif (not ($self->{state} eq 'initial' or $self->{state} eq 'waiting')) {
    return Promise->reject ("Connection is busy");
  }

  $self->{id} = $req->{id} = $self->{transport}->id . '.' . ++$self->{req_id};
  if (DEBUG) {
    warn "$req->{id}: ========== $$ @{[__PACKAGE__]}\n";
    warn "$req->{id}: @{[scalar gmtime]}\n";
  }

  $self->{request} = $req;
  $self->{response} = {status => 200, reason => 'OK', version => '0.9',
                       headers => []};
  $self->{state} = 'before response';
  # XXX Connection: close
  if ($args{ws}) {
    $self->{ws_state} = 'CONNECTING';
    $self->{ws_key} = encode_base64 join ('', map { pack 'C', rand 256 } 1..16), '';
    push @{$req->{headers} ||= []},
        ['Sec-WebSocket-Key', $self->{ws_key}],
        ['Sec-WebSocket-Version', '13'];
    $self->{ws_protos} = $args{ws_protocols} || [];
    if (@{$self->{ws_protos}}) {
      push @{$req->{headers}},
          ['Sec-WebSocket-Protocol', join ',', @{$self->{ws_protos}}];
    }
    # XXX extension
  }
  my $req_done = Promise->new (sub { $self->{request_done} = $_[0] });
  my $header = join '',
      "$method $url HTTP/1.1\x0D\x0A",
      (map { "$_->[0]: $_->[1]\x0D\x0A" } @{$req->{headers} || []}),
      "\x0D\x0A";
  if (DEBUG) {
    for (split /\x0A/, $header) {
      warn "$req->{id}: S: @{[_e4d $_]}\n";
    }
  }
  $self->{request_state} = 'sending headers';
  $self->{transport}->push_write (\$header);
  if ($self->{to_be_sent_length} <= 0) {
    $self->{transport}->push_promise->then (sub { # XXX can fail
      $self->{request_state} = 'sent';
      $self->_ev ('requestsent');
      $self->_next if $self->{state} eq 'sending';
    });
  } else {
    $self->{transport}->push_promise->then (sub {
      $self->{request_state} = 'sending body';
    });
  }
  if (DEBUG) {
    $req_done = $req_done->then (sub {
      warn "$req->{id}: ==========\n";
    });
  }
  return $req_done;
} # send_request_headers

sub send_data ($$;%) {
  my ($self, $ref, %args) = @_;
  my $is_body = (defined $self->{to_be_sent_length} and
                 $self->{to_be_sent_length} > 0);
  my $is_tunnel = (defined $self->{state} and
                   ($self->{state} eq 'tunnel' or
                    $self->{state} eq 'tunnel sending'));
  croak "Bad state"
      if not $is_body and not $is_tunnel;
  croak "Data too large"
      if $is_body and $self->{to_be_sent_length} < length $$ref;
  croak "Data is utf8-flagged" if utf8::is_utf8 $$ref;
  return unless length $$ref;

  if (DEBUG > 1) {
    for (split /\x0A/, $$ref, -1) {
      warn "$self->{request}->{id}: S: @{[_e4d $_]}\n";
    }
  }

  if (defined $self->{ws_state} and $self->{ws_state} eq 'OPEN') {
    my @data;
    my $mask = $self->{ws_encode_mask_key};
    my $o = $self->{ws_sent_length};
    for (0..((length $$ref)-1)) {
      push @data, substr ($$ref, $_, 1) ^ substr ($mask, ($o+$_) % 4, 1);
    }
    $self->{ws_sent_length} += length $$ref;
    $self->{to_be_sent_length} -= length $$ref;
    $self->{transport}->push_write (\join '', @data);
  } else {
    $self->{transport}->push_write ($ref);

    if ($is_body) {
      $self->{to_be_sent_length} -= length $$ref;
      if ($self->{to_be_sent_length} <= 0) {
        $self->{transport}->push_promise->then (sub {
          $self->{request_state} = 'sent';
          $self->_ev ('requestsent');
          $self->_next if $self->{state} eq 'sending';
        });
      }
    } # $is_body
  }
} # send_data

sub abort ($;%) {
  my ($self, %args) = @_;
  if (not defined $self->{state}) {
    return Promise->reject ("Connection has not been established");
  }

  $self->{no_new_request} = 1;
  $self->{request_state} = 'sent';
  delete $self->{to_be_sent_length};
  $self->{transport}->abort (%args);

  return $self->{closed};
} # abort

sub onevent ($;$) {
  if (@_ > 1) {
    $_[0]->{onevent} = $_[1];
  }
  return $_[0]->{onevent} ||= sub { };
} # onevent

sub _ev ($$;$$) {
  my $self = shift;
  my $req = $self->{request};
  if (DEBUG) {
    warn "$req->{id}: $_[0] @{[scalar gmtime]}\n";
    if ($_[0] eq 'data' and DEBUG > 1) {
      for (split /\x0D?\x0A/, $_[1], -1) {
        warn "$req->{id}: R: @{[_e4d $_]}\n";
      }
    } elsif ($_[0] eq 'text' and DEBUG > 1) {
      for (split /\x0D?\x0A/, $_[1], -1) {
        warn "$req->{id}: R: @{[_e4d_t $_]}\n";
      }
    } elsif ($_[0] eq 'headers') {
      if ($_[1]->{version} eq '0.9') {
        warn "$req->{id}: R: HTTP/0.9\n";
      } else {
        warn "$req->{id}: R: HTTP/$_[1]->{version} $_[1]->{status} $_[1]->{reason}\n";
        for (@{$_[1]->{headers}}) {
          warn "$req->{id}: R: @{[_e4d $_->[0]]}: @{[_e4d $_->[1]]}\n";
        }
      }
      warn "$req->{id}: + WS established\n" if DEBUG and $_[2];
    } elsif ($_[0] eq 'complete') {
      my $err = join ' ',
          $_[1]->{reset} ? 'reset' : (),
          $self->{response}->{incomplete} ? 'incomplete' : (),
          $_[1]->{failed} ? 'failed' : (),
          $_[1]->{cleanly} ? 'cleanly' : (),
          $_[1]->{can_retry} ? 'retryable' : (),
          defined $_[1]->{errno} ? 'errno=' . $_[1]->{errno} : (),
          defined $_[1]->{message} ? 'message=' . $_[1]->{message} : (),
          defined $_[1]->{status} ? 'status=' . $_[1]->{status} : (),
          defined $_[1]->{reason} ? 'reason=' . $_[1]->{reason} : ();
      warn "$req->{id}: + @{[_e4d $err]}\n" if length $err;
    } elsif ($_[0] eq 'ping') {
      if ($_[2]) {
        warn "$req->{id}: R: pong data=@{[_e4d $_[1]]}\n";
      } else {
        warn "$req->{id}: R: data=@{[_e4d $_[1]]}\n";
      }
    }
  }
  if ($_[0] eq 'complete') {
    (delete $self->{request_done})->();
  }
  $self->onevent->($self, $req, @_);
} # _ev

sub DESTROY ($) {
  $_[0]->abort if defined $_[0]->{transport};

  local $@;
  eval { die };
  warn "Reference to @{[ref $_[0]]} is not discarded before global destruction\n"
      if $@ =~ /during global destruction/;
} # DESTROY

1;

=head1 LICENSE

Copyright 2016 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
