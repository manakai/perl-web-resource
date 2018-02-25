package Web::Transport::PlatformInfo;
use strict;
use warnings;
our $VERSION = '1.0';
use Carp;
use Web::Transport::_PlatformDefs;

sub new_default ($) {
  return bless {ua_key => join $;, 'desktop', 'windows', 'chrome'}, $_[0];
} # new_default

sub new_mobile ($) {
  return bless {ua_key => join $;, 'mobile', 'android', 'chrome'}, $_[0];
} # new_mobile

sub new_from_device_os_navigator ($$$$) {
  croak "Bad device, os, navigator combination ($_[1], $_[2], $_[3])"
      unless defined $Web::Transport::_PlatformDefs->{ua}->{$_[1], $_[2], $_[3]};
  return bless {ua_key => join $;, $_[1], $_[2], $_[3]}, $_[0];
} # new_from_device_os_navigator

sub user_agent ($) {
  return $Web::Transport::_PlatformDefs->{ua}->{$_[0]->{ua_key}};
} # user_agent

# XXX setter
sub accept_language ($) {
  return 'en-US';
} # accept_language

1;

=head1 LICENSE

Copyright 2018 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
