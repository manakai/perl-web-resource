package Unix;
use strict;
use warnings;
our $VERSION = '2.0';
use TCPTransport;
push our @ISA, qw(TCPTransport);

1;

=head1 LICENSE

Copyright 2016-2017 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
