package Web::Transport::ASN1;
use strict;
use warnings;
use warnings FATAL => 'recursion';
use Net::SSLeay;

## This is a very simplified implementation of DER decoder.  This
## module should only be invoked from Web::Transport::* modules.

sub decode_der ($;%);
sub decode_der ($;%) {
  my @s = ref $_[0] ? @{+shift} : split //, shift;
  my %args = @_;
  my $result = [];
  while (@s) {
    my $s = ord shift @s;
    my $tag = 0b11111 & $s;
    if ($tag == 0b11111) {
      return undef; # not supported
    }
    my $is_constructed = 0b100000 & $s;
    my $class = 0b11000000 & $s;

    return undef unless @s;
    my $length = ord shift @s;
    if ($length == 0x80) {
      ## Terminated by 0x00 0x00
      return undef; # not supported
    } elsif ($length & 0x80) {
      my $byte_length = $length & 0x7F;
      $length = 0;
      while ($byte_length > 0) {
        return undef unless @s;
        my $s = ord shift @s;
        $length = $length * 0x100 + $s;
        $byte_length--;
      }
    }

    my @data;
    while ($length > 0) {
      return undef unless @s;
      push @data, shift @s;
      $length--;
    }

    if ($class == 0 and not $is_constructed) {
      if ($tag == 1) {
        if (@data == 1 and $data[0] eq "\x00") {
          push @$result, ['BOOLEAN', 0];
          next;
        } elsif (@data == 1 and $data[0] eq "\xFF") {
          push @$result, ['BOOLEAN', 1];
          next;
        }
      } elsif ($tag == 2) {
        my $v = '';
        for (@data) {
          $v .= sprintf '%02X', ord $_;
        }
        $v = '00' unless length $v;
        if (4 >= length $v) {
          push @$result, ['int', hex $v];
        } else {
          push @$result, ['bigint', '0x' . $v] # Math::BigInt->from_hex ($v)
        }
        next;
      } elsif ($tag == 3) { # BIT STRING
        # $data[0] is # of redundant bits at the end of the sequence
        push @$result, ['bytes', (join '', @data[1..$#data])];
        next;
      } elsif ($tag == 4) { # OCTET STRING
        push @$result, ['bytes', (join '', @data)];
        next;
      } elsif ($tag == 5) { # NULL
        if (@data == 0) {
          push @$result, ['NULL'];
          next;
        }
      } elsif ($tag == 6) { # OBJECT IDENTIFIER
        if (@data) {
          eval {
            push @$result, ['oid', join '.',
                            int ((ord $data[0]) / 40),
                            (ord $data[0]) % 40,
                            unpack 'w*', join '', @data[1..$#data]];
          }; # unpack can throw
          return undef if $@;
          next;
        }
      } elsif ($tag == 10) { # ENUMERATED
        if (@data == 1) {
          push @$result, ['ENUMERATED', ord $data[0]];
          next;
        }
      } elsif ($tag == 0x0C) { # 12 UTF8String
        push @$result, ['UTF8String', (join '', @data)];
        next;
      } elsif ($tag == 0x12) { # 18 NumericString
        push @$result, ['NumericString', (join '', @data)];
        next;
      } elsif ($tag == 0x13) { # 19 PrintableString
        push @$result, ['PrintableString', (join '', @data)];
        next;
      } elsif ($tag == 0x14) { # 20 TeletexString
        push @$result, ['TeletexString', (join '', @data)];
        next;
      # 21 VideotexString
      } elsif ($tag == 0x16) { # 22 IA5String
        push @$result, ['IA5String', (join '', @data)];
        next;
      } elsif ($tag == 0x17) { # 23 UTCTime
        push @$result, ['UTCTime', join '', @data];
        next;
      } elsif ($tag == 0x18) { # 24 GeneralizedTime
        push @$result, ['GeneralizedTime', join '', @data];
        next;
      # 25 GraphicString
      # 26 VisibleString
      # 27 GeneralString
      } elsif ($tag == 0x1C) { # 28 UniversalString
        push @$result, ['UniversalString', (join '', @data)];
        next;
      } elsif ($tag == 0x1E) { # 30 BMPString
        push @$result, ['BMPString', (join '', @data)];
        next;
      }
    } elsif ($class == 0 and $is_constructed) {
      if ($tag == 16) {
        if (defined $args{depth} and $args{depth} > 0) {
          push @$result, ['SEQUENCE', decode_der \@data, depth => $args{depth} - 1];
          return undef unless defined $result->[-1]->[1];
          next;
        } else {
          push @$result, ['SEQUENCE unparsed', join '', @data];
          next;
        }
      } elsif ($tag == 17) {
        if (defined $args{depth} and $args{depth} > 0) {
          push @$result, ['SET', decode_der \@data, depth => $args{depth} - 1];
          return undef unless defined $result->[-1]->[1];
          next;
        } else {
          push @$result, ['SET unparsed', join '', @data];
          next;
        }
      }
    } elsif ($class == 0x80) {
      push @$result, ['contextual', $tag, join '', @data];
      next;
    }

    ## Not supported
    push @$result, ['unknown', $class, $is_constructed, $tag, \@data];
  } # @s
  return $result;
} # decode_der

sub read_sequence ($$$) {
  my (undef, $def, $parsed) = @_;
  return undef unless defined $parsed and $parsed->[0] eq 'SEQUENCE';
  my $result = {};
  my $expected = [@$def];
  for (@{$parsed->[1]}) {
    my $next = shift @$expected;
    my $matched;
    while (1) {
      if (defined $next->{seq} and
          $_->[0] eq 'contextual' and $_->[1] == $next->{seq}) {
        $matched = 1;
        last;
      } elsif ($next->{types}->{$_->[0]}) {
        $matched = 1;
        last;
      } elsif (defined $next->{seq} or $next->{optional}) {
        #
      } else {
        last;
      }
      $next = shift @$expected;
      last if not defined $next;
    }
    if ($matched) {
      $result->{$next->{name}} = $_;
    } else {
      warn "Got |$_->[0]| (|$next->{name}| value expected)";
      return undef;
    }
  }
  return $result;
} # read_sequence

sub read_name ($$) {
  my ($self, $parsed) = @_;
  # Name ::= CHOICE { rdnSequence RDNSequence }
  # RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
  return undef unless defined $parsed and $parsed->[0] eq 'SEQUENCE';
  my $result = [];
  for my $rdn (@{$parsed->[1]}) {
    ## RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue
    return undef unless $rdn->[0] eq 'SET';
    my $v = [];
    for my $tv (@{$rdn->[1]}) {
      ## AttributeTypeAndValue ::= SEQUENCE { ... }
      return undef unless $tv->[0] eq 'SEQUENCE' and
          @{$tv->[1]} >= 2 and
          $tv->[1]->[0]->[0] eq 'oid';

      push @$v, [$tv->[1]->[0]->[1], $tv->[1]->[1]->[0], $tv->[1]->[1]->[1]];
    }
    push @$result, $v;
  } # $rdn
  return $result;
} # read_name

my $OIDDef = {};
sub find_oid ($$) {
  my $in = $_[1];
  return $OIDDef->{$in} if exists $OIDDef->{$in};

  my $obj = Net::SSLeay::OBJ_txt2obj $in;
  return $OIDDef->{$in} = undef unless $obj; # bad input

  my $def = {};
  my $oid = Net::SSLeay::OBJ_obj2txt $obj, 1;
  $def->{oid} = $oid;
  $OIDDef->{$oid} = $def;

  my $nid = Net::SSLeay::OBJ_obj2nid $obj;
  if ($nid) {
    $def->{long_name} = Net::SSLeay::OBJ_nid2ln $nid;
    $def->{short_name} = Net::SSLeay::OBJ_nid2sn $nid;
    $OIDDef->{$def->{long_name}} = $OIDDef->{$def->{short_name}} = $def;
  }

  return $def;
} # find_oid

1;

=head1 LICENSE

Copyright 2018 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
