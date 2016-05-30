package Web::Transport::ASN1;
use strict;
use warnings;

## This is a very simplified implementation of DER decoder.  This
## module should only be invoked from Web::Transport::* modules.

sub decode_der ($;%);
sub decode_der ($;%) {
  my @s = split //, shift;
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
        my $v = 0;
        for (@data) {
          $v = $v * 0x100 + ord $_;
        }
        push @$result, ['INTEGER', $v];
        next;
      } elsif ($tag == 3) { # BIT STRING
        if (@data > 0 and $data[0] eq "\x00") {
          push @$result, ['bytes', (join '', @data[1..$#data])];
          next;
        }
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
      } elsif ($tag == 24) { # GeneralizedTime
        push @$result, ['GeneralizedTime', join '', @data];
        next;
      }
    } elsif ($class == 0 and $is_constructed) {
      if ($tag == 16) {
        if (defined $args{depth} and $args{depth} > 0) {
          push @$result, ['SEQUENCE', decode_der join ('', @data), depth => $args{depth} - 1];
          return undef unless defined $result->[-1]->[1];
          next;
        } else {
          push @$result, ['SEQUENCE unparsed', join '', @data];
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

1;
