use strict;
use warnings;
use Path::Tiny;
use lib path (__FILE__)->parent->parent->child ('lib')->stringify;
use lib glob path (__FILE__)->parent->parent->child ('t_deps/modules/*/lib')->stringify;
use Test::More;
use Test::X1;
use Test::HTCT::Parser;
use Web::MIME::Type;
use Web::MIME::Sniffer;

sub mime ($) {
  return Web::MIME::Type->parse_web_mime_type ($_[0], sub { }); # or undef
} # mime

my $test_data_path = path (__FILE__)->parent->parent->child
    ('t_deps/tests/mime/sniffing');
for my $path ($test_data_path->children (qr/\.dat$/)) {
  my $rel_path = $path->relative ($test_data_path);
  for_each_test $path, {}, sub {
    my $test = $_[0];

    my $input_data = $test->{data}->[0];
    $input_data =~ s/\\x([0-9A-Fa-f]{2})/pack 'C', hex $1/ge;

    my $x = sub {
      if (($test->{computed}->[1]->[0] || '') eq 'supplied') {
        return $_[0]->as_valid_mime_type;
      } else {
        return $test->{computed}->[0];
      }
    };

    my $ct_type = $test->{'content-type'}->[1]->[0] || '';
    if ($ct_type eq '') {
      test {
        my $c = shift;
        my $sniffer = Web::MIME::Sniffer->new;
        $sniffer->supported_image_types->{$_} = 1 for qw(image/jpeg);

        my $content_type = Web::MIME::Type->parse_web_mime_type
            ($test->{'content-type'}->[0]);
        my $st = $sniffer->detect ($content_type, $input_data);
        is $st->as_valid_mime_type_with_no_params, $x->($content_type);

        done $c;
      } n => 1, name => [$rel_path, $test->{name}->[0]];
    } elsif ($ct_type eq 'unknown') {
      for my $ct (undef, 'application/unknown', 'unknown/unknown',
                  'text', '{content_type}', '') {
        test {
          my $c = shift;
          my $sniffer = Web::MIME::Sniffer->new;
          $sniffer->supported_image_types->{$_} = 1 for qw(image/jpeg);

          my $content_type = defined $ct ? Web::MIME::Type->parse_web_mime_type ($ct) : undef;
          my $st = $sniffer->detect ($content_type, $input_data);
          is $st->as_valid_mime_type_with_no_params, $x->($content_type);

          done $c;
        } n => 1, name => [$rel_path, $test->{name}->[0], $ct];
      } # $ct
    } elsif ($ct_type eq 'image') {
      for my $img_type (qw(image/png image/gif image/jpeg)) {
        my $content_type = Web::MIME::Type->parse_web_mime_type ($img_type);

        test {
          my $c = shift;
          test {
            my $sniffer = Web::MIME::Sniffer->new;
            $sniffer->supported_image_types->{$img_type} = 1;
            my $st = $sniffer->detect ($content_type, $input_data);
            is $st->as_valid_mime_type_with_no_params, $img_type;
          } $c, name => 'If it is the only supported type';

          test {
            my $sniffer = Web::MIME::Sniffer->new;
            my $st = $sniffer->detect ($content_type, $input_data);
            is $st->as_valid_mime_type_with_no_params, $img_type;
          } $c, name => 'If there is no supported type';

          test {
            my $sniffer = Web::MIME::Sniffer->new;
            $sniffer->supported_image_types->{$_} = 1 for qw(
              image/png image/jpeg image/gif image/bmp image/vnd.microsoft.icon
            );
            my $st = $sniffer->detect ($content_type, $input_data);
            is $st->as_valid_mime_type_with_no_params, $x->($content_type);
          } $c, name => 'If all types are supported';

          done $c;
        } n => 3, name => [$rel_path, $img_type];
      } # $img_type
    } else {
      die "Bad ct_type |$ct_type|";
    }
  };
} # $path

## XXX We should test image sniffing rules standalone actually...

run_tests;

## License: Public Domain.
