package Transport::UNIXDomainSocket;
use strict;
use warnings;
use Carp qw(croak);
use Transport::TCP;
push our @ISA, qw(Transport::TCP);

sub new ($%) {
  my $self = bless {}, shift;
  my $args = $self->{args} = {@_};
  $args->{addr} = 'unix/';
  $args->{port} = delete $args->{path};
  croak "No |file_name| specified" unless defined $args->{port};
  croak "Bad |id|" if defined $args->{id} and utf8::is_utf8 ($args->{id});
  $self->{id} = (defined $args->{id} ? $args->{id} : int rand 100000);
  return $self;
} # new

sub type ($) { return 'UNIX' }
sub request_mode ($) { 'default' }

1;
