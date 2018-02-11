package Web::Transport::DataURL;
use strict;
use warnings;
our $VERSION = '1.0';
use Carp;

sub new_from_mime_and_scalarref ($$$) {
  my ($class, $mime, $ref) = @_;
  croak "Body is not a scalar reference" unless ref $ref eq 'SCALAR';
  croak "Body is utf8-flagged" if utf8::is_utf8 $$ref;
  return bless {mime_type => $mime, body_ref => $ref}, $class;
} # new_from_mime_and_scalarref

sub mime_type ($) { $_[0]->{mime_type} }
sub body_ref ($) { $_[0]->{body_ref} }

1;

=head1 LICENSE

Copyright 2018 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
