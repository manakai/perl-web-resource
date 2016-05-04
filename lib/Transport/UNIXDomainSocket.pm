package Transport::UNIXDomainSocket;
use strict;
use warnings;
use Transport::TCP;
push our @ISA, qw(Transport::TCP);

sub new ($%) {
  my $self = bless {}, shift;
  $self->{id} = int rand 100000;
  my $args = $self->{args} = {@_};
  $args->{addr} = 'unix/';
  $args->{port} = delete $args->{file_name};
  return $self;
} # new

sub type ($) { return 'UNIX' }

1;
