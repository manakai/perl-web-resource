package Web::Transport::PKI::Name;
use strict;
use warnings;
our $VERSION = '1.0';
use Web::Transport::TypeError;
use Web::Transport::NetSSLeayError;
use Web::Encoding;
use Web::Transport::ASN1;
use Net::SSLeay;

push our @CARP_NOT, qw(Web::Transport::TypeError
                       Web::Transport::NetSSLeayError);

sub create ($$) {
  my ($class, $in) = @_;

  return $in if UNIVERSAL::isa ($in, $class);

  my $parsed = [];
  if (not defined $in) {
    #
  } elsif (ref $in eq 'HASH') {
    my $vv = {};
    for (sort { $a cmp $b } keys %$in) {
      my $oid = Web::Transport::ASN1->find_oid ($_);
      die new Web::Transport::TypeError ("Bad key |".$_."|")
          unless defined $oid;
      my $v = $in->{$_};
      next unless defined $v;
      if ($v =~ m{\A[0-9A-Za-z'+,./:=?\x20-]*\z}) {
        $v = [$oid->{oid}, 'PrintableString', encode_web_utf8 $v];
      } else {
        $v = [$oid->{oid}, 'UTF8String', encode_web_utf8 $v];
      }
      push @{$vv->{$oid->{oid}} ||= []}, $v;
    } # $in

    for (
      '2.5.4.6', # C
      '2.5.4.8', # ST
      '2.5.4.7', # L
      '2.5.4.10', # O
      '2.5.4.11', # OU
      '2.5.4.3', # CN
    ) {
      next unless defined $vv->{$_};
      push @$parsed, map { [$_] } @{delete $vv->{$_}};
    }

    for (sort { $a cmp $b } keys %$vv) {
      push @$parsed, map { [$_] } @{$vv->{$_}};
    }
  } else {
    die new Web::Transport::TypeError ("Bad argument");
  }

  return $class->_new ($parsed);
} # create

sub _new ($$) {
  return bless {parsed => $_[1] || []}, $_[0];
} # new

#  for (0 .. (Net::SSLeay::X509_NAME_entry_count ($name) - 1)) {
#    my $ne = Net::SSLeay::X509_NAME_get_entry ($name, $_)
#        or die Web::Transport::NetSSLeayError->new_current;
#
#    my $obj = Net::SSLeay::X509_NAME_ENTRY_get_object ($ne)
#        or die Web::Transport::NetSSLeayError->new_current;
#    my $obj_id = Net::SSLeay::OBJ_obj2txt ($obj, 1);
#    my $obj_nid = Net::SSLeay::OBJ_obj2nid ($obj);
#    my $obj_ln = Net::SSLeay::OBJ_nid2ln $obj_nid;
#    my $obj_sn = Net::SSLeay::OBJ_nid2sn $obj_nid;
#
#    my $s = Net::SSLeay::X509_NAME_ENTRY_get_data ($ne)
#        or die Web::Transport::NetSSLeayError->new_current;
#    my $bytes = Net::SSLeay::P_ASN1_STRING_get ($s, 0);
#    push @{$self->{pairs}}, [$obj_id, $obj_sn, $obj_ln, $bytes];
#  }

sub modify_net_ssleay_name ($$) {
  my ($self, $name) = @_;

  for my $rdn (@{$self->{parsed}}) {
    my $set = 0;
    for (@$rdn) {
      my $type = {
        UTF8String => 12,
        PrintableString => 19,
        TeletexString => 20,
        IA5String => 22,
        UniversalString => 28,
        BMPString => 30,
      }->{$_->[1]} // die Web::Transport::TypeError->new ("Bad type |$_->[1]|");
      Net::SSLeay::X509_NAME_add_entry_by_txt
          ($name, $_->[0], $type, $_->[2], -1, $set)
              or Web::Transport::NetSSLeayError->new_current;
      $set = -1;
    }
  }
} # modify_net_ssleay_name

sub debug_info ($) {
  my $self = $_[0];
  return join ',', map {
    '[' . (join ';', map {
      my $oid = Web::Transport::ASN1->find_oid ($_->[0]);
      ($oid->{short_name} // $oid->{oid} // $_->[0]) . '=' . '(' . ({
        PrintableString => 'P',
        UTF8String => 'U',
      }->{$_->[1]} // $_->[1]) . ')' . (
        $_->[1] eq 'UTF8String' ? decode_web_utf8 $_->[2] : $_->[2]
      );
    } @$_) . ']';
  } @{$self->{parsed}};
} # debug_info

1;

=head1 LICENSE

Copyright 2016-2018 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
