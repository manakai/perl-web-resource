package Web::MIME::Type::Parser;
use strict;
use warnings;
our $VERSION = '1.0';
use Web::MIME::Type;

sub new ($) {
  return bless {}, $_[0];
} # new

sub onerror ($;$) {
  if (@_ > 1) {
    $_[0]->{onerror} = $_[1];
  }
  return $_[0]->{onerror} ||= sub {
    my %opt = @_;
    my @msg = ($opt{type});
    push @msg, $opt{value} if defined $opt{value};
    push @msg, ' at position ' . $opt{index};
    warn join '; ', @msg, "\n";
  };
} # onerror

my $HTTPToken = qr/[\x21\x23-\x27\x2A\x2B\x2D\x2E\x30-\x39\x41-\x5A\x5E-\x7A\x7C\x7E]+/;
my $lws0 = qr/(?>(?>\x0D\x0A)?[\x09\x20])*/;
my $HTTP11QS = qr/"(?>[\x20\x21\x23-\x5B\x5D-\x7E]|\x0D\x0A[\x09\x20]|\x5C[\x00-\x7F])*"/;

sub parse_string ($$) {
  my ($self, $value) = @_;
  my $onerror = $self->onerror;

  ## <https://mimesniff.spec.whatwg.org/#supplied-mime-type-detection-algorithm>
  my $apache_bug;
  if ($value eq "\x74\x65\x78\x74\x2F\x70\x6C\x61\x69\x6E" or
      $value eq "\x74\x65\x78\x74\x2F\x70\x6C\x61\x69\x6E\x3B\x20\x63\x68\x61\x72\x73\x65\x74\x3D\x49\x53\x4F\x2D\x38\x38\x35\x39\x2D\x31" or
      $value eq "\x74\x65\x78\x74\x2F\x70\x6C\x61\x69\x6E\x3B\x20\x63\x68\x61\x72\x73\x65\x74\x3D\x69\x73\x6F\x2D\x38\x38\x35\x39\x2D\x31" or
      $value eq "\x74\x65\x78\x74\x2F\x70\x6C\x61\x69\x6E\x3B\x20\x63\x68\x61\x72\x73\x65\x74\x3D\x55\x54\x46\x2D\x38") {
    $apache_bug = 1;
  }

  $value =~ /\G$lws0/ogc;

  my $type;
  if ($value =~ /\G($HTTPToken)/ogc) {
    $type = $1;
  } else {
    $onerror->(type => 'IMT:no type', # XXXdocumentation
               level => 'm',
               index => pos $value);
    return undef;
  }

  unless ($value =~ m[\G/]gc) {
    $onerror->(type => 'IMT:no /', # XXXdocumentation
               level => 'm',
               index => pos $value);
    return undef;
  }

  my $subtype;
  if ($value =~ /\G($HTTPToken)/ogc) {
    $subtype = $1;
  } else {
    $onerror->(type => 'IMT:no subtype', # XXXdocumentation
               level => 'm',
               index => pos $value); 
    return undef;
  }

  $value =~ /\G$lws0/ogc;

  my $mt = Web::MIME::Type->new_from_type_and_subtype ($type, $subtype);
  $mt->{apache_bug} = 1 if $apache_bug;

  while ($value =~ /\G;/gc) {
    $value =~ /\G$lws0/ogc;
    
    my $attr;
    if ($value =~ /\G($HTTPToken)/ogc) {
      $attr = $1;
    } else {
      $onerror->(type => 'params:no attr', # XXXdocumentation
                 level => 'm',
                 index => pos $value);
      return $mt;
    }

    unless ($value =~ /\G=/gc) {
      $onerror->(type => 'params:no =', # XXXdocumentation
                 level => 'm',
                 index => pos $value);
      return $mt;
    }

    my $v;
    if ($value =~ /\G($HTTPToken)/ogc) {
      $v = $1;
    } elsif ($value =~ /\G($HTTP11QS)/ogc) {
      $v = substr $1, 1, length ($1) - 2;
      $v =~ s/\\(.)/$1/gs;
    } else {
      $onerror->(type => 'params:no value', # XXXdocumentation
                 level => 'm',
                 index => pos $value);
      return $mt;
    }

    $value =~ /\G$lws0/ogc;

    my $current = $mt->param ($attr);
    if (defined $current) {
      ## Surprisingly this is not a violation to the MIME or HTTP spec!
      $onerror->(type => 'params:duplicate attr', # XXXdocumentation
                 level => 'w',
                 value => $attr,
                 index => pos $value);
      next;
    } else {
      $mt->param ($attr => $v);
    }
  }

  if (pos $value < length $value) {
    $onerror->(type => 'params:garbage', # XXXdocumentation
               level => 'm',
               index => pos $value);
  }

  return $mt;
} # parse_string

1;

=head1 LICENSE

Copyright 2007-2018 Wakaba <wakaba@suikawiki.org>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
