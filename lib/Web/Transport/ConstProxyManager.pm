package Web::Transport::ConstProxyManager;
use strict;
use warnings;
our $VERSION = '1.0';
use Promise;
use Web::Host;

sub new_from_arrayref ($$) {
  my $list = [map {
    if (defined $_->{host} and not ref $_->{host}) {
      my $v = {%$_};
      $v->{host} = Web::Host->parse_string ($v->{host});
      $v;
    } else {
      $_;
    }
  } @{$_[1]}];
  return bless $list, $_[0];
} # new_from_arrayref

sub get_proxies_for_url ($$;%) {
  my ($self, $url, %args) = @_;
  return Promise->resolve ($self);
} # get_proxies_for_url

1;

=head1 LICENSE

Copyright 2016-2017 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
