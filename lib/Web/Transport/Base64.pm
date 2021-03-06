package Web::Transport::Base64;
use strict;
use warnings;
use Carp;
use MIME::Base64;
our $VERSION = '2.0';

our @EXPORT = qw(encode_web_base64 decode_web_base64
                 encode_web_base64url decode_web_base64url);

sub import ($;@) {
  my $from_class = shift;
  my ($to_class, $file, $line) = caller;
  no strict 'refs';
  for (@_ ? @_ : @{$from_class . '::EXPORT'}) {
    my $code = $from_class->can ($_)
        or croak qq{"$_" is not exported by the $from_class module at $file line $line};
    *{$to_class . '::' . $_} = $code;
  }
} # import

sub encode_web_base64 ($) {
  croak "Wide character in subroutine entry" if utf8::is_utf8 ($_[0]);
  return '' if not defined $_[0];
  return encode_base64 $_[0], '';
} # encode_web_base64

sub decode_web_base64 ($) {
  my $v = $_[0];
  $v = '' if not defined $v;
  $v =~ s/[\x09\x0A\x0C\x0D\x20]+//g; ## HTML white space
  my $vl = (length $v) % 4;
  if ($vl == 0) {
    $v =~ s/=\z//;
    $v =~ s/=\z//;
  } elsif ($vl == 1) {
    return undef;
  }
  return undef if $v =~ m{[^+/0-9A-Za-z]};
  return decode_base64 $v;
} # decode_web_base64

sub encode_web_base64url ($) {
  my $b64 = encode_web_base64 $_[0];
  $b64 =~ tr{+/=}{-_}d;
  return $b64;
} # encode_web_base64url

sub decode_web_base64url ($) {
  my $x = $_[0];
  return '' if not defined $x;
  $x =~ tr{-_}{+/};
  return undef if $x =~ m{[^+/0-9A-Za-z=]};
  return decode_web_base64 $x;
} # decode_web_base64url

1;

=head1 LICENSE

Copyright 2018-2019 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
