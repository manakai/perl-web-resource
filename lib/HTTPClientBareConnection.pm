package HTTPClientBareConnection;
use strict;
use warnings;
use Promise;
use Transport::TCP;
use HTTP;
use Web::Encoding qw(encode_web_utf8);
use Web::URL::Canonicalize qw(serialize_parsed_url);

sub new_from_addr_and_port ($$$) {
  return bless {addr => $_[1], port => $_[2]}, $_[0];
} # new_from_addr_and_port

sub connect ($) {
  my $self = $_[0];
  return $self->{connect_promise} ||= do {
    my $transport = Transport::TCP->new
        (addr => $self->{addr}, port => $self->{port});
    $self->{http} = HTTP->new (transport => $transport);
    $self->{http}->connect;
  };
} # connect

sub request ($$$$;$) {
  my ($self, $method, $url_record, $headers, $cb) = @_;
  return $self->connect->then (sub {
    return {failed => 1, message => "Bad input URL"}
        unless defined $url_record->{host};
    my $target;
    if ($self->{http}->transport->request_mode eq 'HTTP proxy') {
      local $url_record->{fragment} = undef;
      $target = serialize_parsed_url $url_record;
    } else {
      $target = $url_record->{path} . (defined $url_record->{query} ? '?' . $url_record->{query} : '');
    }
    my $host = $url_record->{host} . (defined $url_record->{port} ? ':' . $url_record->{port} : '');
    $headers = [['Host', encode_web_utf8 $host], ['Connection', 'keep-alive'],
                @$headers];

    my $response;
    my $result;
    $self->{http}->onevent (sub {
      my $http = $_[0];
      my $type = $_[2];
      if ($type eq 'data') {
        if (defined $cb and not defined $result) {
          my $v = $_[3]; # buffer copy!
          Promise->resolve->then (sub { return $cb->($http, $response, $v) });
        }
      } elsif ($type eq 'dataend') {
        if (defined $cb and not defined $result) {
          Promise->resolve->then (sub { return $cb->($http, $response, undef) });
        }
      } elsif ($type eq 'complete') {
        my $exit = $_[3];
        if ($exit->{failed}) {
          $response = undef;
          $result ||= $exit;
        }
      } elsif ($type eq 'headers') {
        my $transport = $_[0]->transport;
        my $res = $_[3];
        if ($transport->request_mode ne 'HTTP proxy' and
            $res->{status} == 407) {
          $response = undef;
          $result ||= {failed => 1, message => 'Status 407 from non-proxy'};
        } else {
          $response = $res;
          if ($transport->type eq 'TLS' and
              not $transport->has_alert) {
            # XXX HSTS, PKP
          }
        }
        if (defined $cb and not defined $result) {
          Promise->resolve->then (sub { return $cb->($http, $response, '') });
        }
      }
    });
    return $self->{http}->send_request_headers
        ({method => $method, target => encode_web_utf8 ($target),
          headers => $headers})->then (sub {
      return $result || $response;
    });
  }, sub {
    return {failed => 1, message => $_[0]};
  });
} # request

sub is_active ($) {
  return 0 unless defined $_[0]->{http};
  return $_[0]->{http}->is_active;
} # is_active

sub close ($) {
  my $self = $_[0];
  return Promise->resolve unless defined $self->{http};
  return $self->{http}->close->then (sub {
    delete $self->{http};
    delete $self->{connect_promise};
    return undef;
  });
} # close

sub abort ($;%) {
  my $self = shift;
  return unless defined $self->{http};
  return $self->{http}->abort (@_)->then (sub {
    delete $self->{http};
    delete $self->{connect_promise};
    return undef;
  });
} # abort

sub DESTROY ($) {
  $_[0]->abort (message => "Aborted by DESTROY of $_[0]");

  local $@;
  eval { die };
  warn "Reference to @{[ref $_[0]]} is not discarded before global destruction\n"
      if $@ =~ /during global destruction/;

} # DESTROY

1;
