package Web::Transport::UnixStream;
use strict;
use warnings;
our $VERSION = '2.0';
use Web::Transport::TCPStream;
push our @ISA, qw(Web::Transport::TCPStream);

1;

=head1 LICENSE

Copyright 2016-2017 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
