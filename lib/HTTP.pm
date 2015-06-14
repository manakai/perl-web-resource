package HTTP;
use strict;
use warnings;
use AnyEvent;
use AnyEvent::Handle;
use AnyEvent::Socket;

sub new_from_host_and_port ($$$) {
  return bless {host => $_[1], port => $_[2]}, $_[0];
} # new_from_host_and_port

sub connect_as_cv ($) {
  my $self = $_[0];
  my $cv = AE::cv;
  tcp_connect $self->{host}, $self->{port}, sub {
    my $fh = shift or die "XXX $!";

    my $handle; $handle = AnyEvent::Handle->new
        (fh => $fh,
         onerror => sub {
           my ($hdl, $fatal, $msg) = @_;
           AE::log error => $msg;
           $handle->destroy;
           $self->onclose->($msg);
           $cv->send;
         },
         on_eof => sub {
           my ($handle) = @_;
           $self->onclose->(undef);
           $cv->send;
         });
    $handle->push_write ("GET /\x0D\x0A");

    $handle->on_read (sub {
      my ($handle) = @_;
      $self->ondata->($handle->{rbuf});
      $handle->{rbuf} = '';
    });
  };
  return $cv;
} # connect_as_cv

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
