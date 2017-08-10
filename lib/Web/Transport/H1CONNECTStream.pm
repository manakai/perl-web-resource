package Web::Transport::H1CONNECTStream;
use strict;
use warnings;
our $VERSION = '2.0';
use AnyEvent;
use Promise;
use Promised::Flow;
use Web::DOM::TypeError;
use Web::Transport::ProtocolError;
use Web::Transport::HTTPStream;

push our @CARP_NOT, qw(
  Web::DOM::TypeError Web::Transport::ProtocolError::HTTPParseError
  Web::Transport::HTTPStream
);

sub _tep ($) {
  return Promise->reject (Web::DOM::TypeError->new ($_[0]));
} # _tep

##   parent - The hash reference used as the argument to the
##   Web::Transport::HTTPStream->new method.
##
##   target - The |request-target| of the HTTP |CONNECT| request.
##
##   debug
sub create ($$) {
  my ($class, $args) = @_;

  return _tep "Bad |parent|"
      unless defined $args->{parent} and ref $args->{parent} eq 'HASH';
  return _tep "Bad |parent|"
      if defined $args->{parent}->{class};
  return _tep "|server| not allowed"
      if $args->{server};
  return _tep "Bad |target|"
      unless defined $args->{target} and not utf8::is_utf8 ($args->{target});

  my $parent = $args->{parent};
  if ($args->{debug}) {
    $parent = {%$parent, debug => 1} # 1, not $args->{debug}
        unless defined $parent->{debug};
    if (defined $parent->{parent} and ref $parent->{parent} eq 'HASH') {
      $parent->{parent} = {%{$parent->{parent}}, debug => $args->{debug}}
          unless defined $parent->{parent}->{debug};
    }
  }
  my $http = Web::Transport::HTTPStream->new ($parent);

  my $info = {
    type => 'CONNECT',
    layered_type => 'CONNECT',
  };
  $info->{closed} = $http->closed;

  return $http->ready->then (sub {
    $info->{parent} = $http->info;
    $info->{layered_type} .= '/' . $info->{parent}->{layered_type};
    $info->{id} = $info->{parent}->{id} . 'C';
    warn "$info->{id}: $info->{type}: start (target |$args->{target}|)\n"
        if $args->{debug};

    return $http->send_request ({
      method => 'CONNECT',
      target => $args->{target},
      headers => [
        [Host => $args->{target}],
        ['Proxy-Connection' => 'keep-alive'],
        ['User-Agent', 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.87 Safari/537.36'], # XXX
        # XXX additional headers
      ],
    })->then (sub {
      my $stream = $_[0]->{stream};
      return $stream->headers_received->then (sub {
        my $res = $_[0];
        if ($res->{status} == 200) {
          $info->{writable} = $res->{writable};
          $info->{readable} = $res->{readable};

          if ($args->{debug}) {
            warn "$info->{id}: $info->{type}: ready\n";
            $info->{closed}->then (sub {
              warn "$info->{id}: $info->{type}: closed\n";
            });
          }
          return $info;

        # XXX 407
        } else {
          $res->{body}->cancel if defined $res->{body};
          die Web::Transport::ProtocolError::HTTPParseError->_new_fatal
              ("HTTP |$res->{status}| response"); # XXX associate $res
        }
      });
    });
  })->catch (sub {
    my $error = Web::DOM::Error->wrap ($_[0]);

    return Promise->resolve->then (sub {
      if (defined $http) {
        return $http->closed unless $http->is_active;
        return $http->abort ($error);
      }
    })->then (sub {
      if ($args->{debug} and defined $info->{id}) {
        warn "$info->{id}: $info->{type}: failed ($error)\n";
      }

      # XXX provide $info for application

      die $error;
    });
  });
} # create

1;

=head1 LICENSE

Copyright 2016-2017 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
