use strict;
use warnings;
use Path::Tiny;
use lib path (__FILE__)->parent->parent->child ('lib')->stringify;
use lib glob path (__FILE__)->parent->parent->child ('t_deps/modules/*/lib')->stringify;
use Test::More;
use Test::HTCT::Parser;
use Test::X1;
use Web::MIME::Type;

# ------ Instantiation ------

test {
  my $c = shift;
  my $mt = Web::MIME::Type->new_from_type_and_subtype ('text', 'plain');
  isa_ok $mt, 'Web::MIME::Type';

  is $mt->type, 'text';
  is $mt->subtype, 'plain';
  is $mt->mime_type_portion, 'text/plain';
  is $mt->as_valid_mime_type_with_no_params, 'text/plain';
  is $mt->as_valid_mime_type, 'text/plain';
  done $c;
} n => 6, name => '_new_from_type_and_subtype';

test {
  my $c = shift;
  my $mt = Web::MIME::Type->new_from_type_and_subtype ('tEXt', 'pLAin');
  isa_ok $mt, 'Web::MIME::Type';

  is $mt->type, 'text';
  is $mt->subtype, 'plain';
  is $mt->mime_type_portion, 'text/plain';
  is $mt->as_valid_mime_type_with_no_params, 'text/plain';
  is $mt->as_valid_mime_type, 'text/plain';
  done $c;
} n => 6, name => '_new_from_type_and_subtype_2';

for_each_test (path (__FILE__)->parent->parent->child ('t_deps/tests/mime/types.dat'), {
  data => {is_prefixed => 1},
  errors => {is_list => 1},
  result => {is_prefixed => 1},
}, sub {
  my ($test, $opts) = @_;
  
  test {
    my $c = shift;
    my @errors;
    my $onerror = sub {
      my %opt = @_;
      push @errors, join ';',
          $opt{index},
          $opt{type},
          defined $opt{value} ? $opt{value} : '',
          $opt{level};
    }; # $onerror
    
    my $parsed = Web::MIME::Type->parse_web_mime_type
        ($test->{data}->[0], $onerror);
    
    if ($test->{errors}) {
      is join ("\n", sort {$a cmp $b} @errors),
         join ("\n", sort {$a cmp $b} @{$test->{errors}->[0]}),
         '#errors';
    } else {
      warn qq[No #errors section: "$test->{data}->[0]];
    }

    my $expected_result = defined $test->{result}->[0] ? $test->{result}->[0] : '';
    my $actual_result = '';
    if ($parsed) {
      $actual_result .= $parsed->type . "\n";
      $actual_result .= $parsed->subtype . "\n";
      for my $attr (@{$parsed->attrs}) {
        $actual_result .= $attr . "\n";
        $actual_result .= $parsed->param ($attr) . "\n";
      }
      $expected_result .= "\n" if length $actual_result;
    }
    is $actual_result, $expected_result, '#result';
    done $c;
  } n => 2, name => ['parser', $opts->{line_number}, $test->{data}->[0]];
});

# ------ Accessors ------

test {
  my $c = shift;
  my $mt = Web::MIME::Type->new_from_type_and_subtype ('image', 'png');
  is $mt->type, 'image';
  $mt->type ('Audio');
  is $mt->type, 'audio';
  is $mt->mime_type_portion, 'audio/png';
  is $mt->as_valid_mime_type, 'audio/png';
  done $c;
} n => 4, name => 'type';

test {
  my $c = shift;
  my $mt = Web::MIME::Type->new_from_type_and_subtype ('modeL', 'vrmL');
  is $mt->subtype, 'vrml';
  $mt->subtype ('BMP');
  is $mt->subtype, 'bmp';
  is $mt->mime_type_portion, 'model/bmp';
  is $mt->as_valid_mime_type, 'model/bmp';
  done $c;
} n => 4, name => 'subtype';

test {
  my $c = shift;
  my $mt = Web::MIME::Type->new_from_type_and_subtype ('message', 'rfc822');
  is $mt->param ('charset'), undef;
  $mt->param (charset => '');
  is $mt->param ('charset'), '';
  $mt->param (charset => 0);
  is $mt->param ('charset'), 0;
  $mt->param (charset => 'us-ASCII');
  is $mt->param ('charset'), 'us-ASCII';
  is $mt->param ('CHArset'), 'us-ASCII';
  $mt->param (chARSet => 'iso-2022-JP');
  is $mt->param ('CHARSET'), 'iso-2022-JP';
  done $c;
} n => 6, name => 'param';

for my $input (
  'text/plain',
  'text/plain; charset=iso-8859-1',
  'text/plain; charset=ISO-8859-1',
  'text/plain; charset=UTF-8',
) {
  test {
    my $c = shift;
    my $mime = Web::MIME::Type->parse_web_mime_type ($input);
    ok $mime->apache_bug;
    done $c;
  } n => 1;
}

for my $input (
  'text/html',
  'TEXT/PLAIN',
  'text/plain; charset=utf-8',
  'text/html; charset=UTF-8',
  'text/plain;charset=UTF-8',
  'application/octet-stream',
  'text/plain; charset=utf-8;',
  'text/plain; charset=utf-8; charset=iso-8859-1',
) {
  test {
    my $c = shift;
    my $mime = Web::MIME::Type->parse_web_mime_type ($input);
    ok ! $mime->apache_bug;
    done $c;
  } n => 1;
}

## ------ Properties ------

for my $test (
  ['text', 'plain', 0],
  ['text', 'html', 0],
  ['text', 'css', 1],
  ['text', 'javascript', 0],
  ['text', 'xsl', 1],
  ['text', 'xml', 0],
  ['text', 'xslt', 0],
  ['application', 'xslt+xml', 1],
  ['application', 'xml', 0],
  ['application', 'octet-stream', 0],
  ['x-unknown', 'x-unknown', 0],
) {
  test {
    my $c = shift;
    my $mt = Web::MIME::Type->new_from_type_and_subtype ($test->[0], $test->[1]);
    is !!$mt->is_styling_lang, !!$test->[2];
    done $c;
  } n => 1, name => ['is_styling_lang', $test->[0], $test->[1]];
}

for my $test (
  ['text', 'plain', 0, 0],
  ['text', 'html', 0, 0],
  ['text', 'css', 0, 0],
  ['text', 'xsl', 0, 0],
  ['text', 'xslt', 0, 0],
  ['text', 'xml', 0, 0],
  ['application', 'xml', 0, 0],
  ['application', 'octet-stream', 0, 0],
  ['application', 'xslt+xml', 0, 0],
  ['x-unknown', 'x-unknown', 0, 0],
  ['text', 'javascript', 1, 1],
  ['text', 'javascript1.0', 1, 1],
  ['text', 'javascript1.1', 1, 1],
  ['text', 'javascript1.2', 1, 1],
  ['text', 'javascript1.3', 1, 1],
  ['text', 'javascript1.4', 1, 1],
  ['text', 'javascript1.5', 1, 1],
  ['text', 'jscript', 1, 1],
  ['text', 'livescript', 1, 1],
  ['text', 'ecmascript', 1, 1],
  ['text', 'x-ecmascript', 1, 1],
  ['text', 'x-javascript', 1, 1],
  ['application', 'ecmascript', 1, 1],
  ['application', 'javascript', 1, 1],
  ['application', 'x-ecmascript', 1, 1],
  ['application', 'x-javascript', 1, 1],
  ['text', 'vbscript', 1, 0],
  ['text', 'vbs', 1, 0],
  ['text', 'tcl', 1, 0],
) {
  test {
    my $c = shift;
    my $mt = Web::MIME::Type->new_from_type_and_subtype ($test->[0], $test->[1]);
    is !!$mt->is_scripting_lang, !!$test->[2];
    is !!$mt->is_javascript, !!$test->[3];
    done $c;
  } n => 2, name => ['is_scripting_lang', $test->[0], $test->[1]];
}

test {
  my $c = shift;
  for (
      ['text', 'plain', 1],
      ['text', 'html', 1],
      ['text', 'css', 1],
      ['text', 'xsl', 1],
      ['text', 'xslt', 1],
      ['application', 'xslt+xml', 1],
      ['image', 'bmp', 0],
      ['message', 'rfc822', 1],
      ['message', 'x-unknown', 1],
      ['x-unknown', 'x-unknown', 0],
      ['application', 'xhtml+xml', 1],
      ['model', 'x-unknown', 0],
      ['image', 'svg+xml', 1],
      ['application', 'octet-stream', 0],
      ['text', 'x-unknown', 1],
      ['video', 'x-unknown+xml', 1],
      ['text', 'xml', 1],
      ['application', 'xml', 1],
  ) {
    my $mt = Web::MIME::Type->new_from_type_and_subtype ($_->[0], $_->[1]);
    is !!$mt->is_text_based, !!$_->[2];
  }
  done $c;
} n => 18, name => 'is_text_based';

test {
  my $c = shift;
  for (
      ['text', 'plain', 0],
      ['text', 'html', 0],
      ['text', 'css', 0],
      ['text', 'xsl', 0],
      ['text', 'xslt', 0],
      ['application', 'xslt+xml', 0],
      ['image', 'bmp', 0],
      ['message', 'rfc822', 1],
      ['message', 'x-unknown', 1],
      ['x-unknown', 'x-unknown', 0],
      ['application', 'xhtml+xml', 0],
      ['model', 'x-unknown', 0],
      ['image', 'svg+xml', 0],
      ['application', 'octet-stream', 0],
      ['text', 'x-unknown', 0],
      ['video', 'x-unknown+xml', 0],
      ['text', 'xml', 0],
      ['application', 'xml', 0],
      ['multipart', 'mixed', 1],
      ['multipart', 'example', 1],
      ['multipart', 'rfc822+xml', 1],
  ) {
    my $mt = Web::MIME::Type->new_from_type_and_subtype ($_->[0], $_->[1]);
    is !!$mt->is_composite_type, !!$_->[2];
  }
  done $c;
} n => 21, name => 'is_composite';

test {
  my $c = shift;
  for (
      ['text', 'plain', 0],
      ['text', 'html', 0],
      ['text', 'css', 0],
      ['text', 'xsl', 0],
      ['text', 'xslt', 0],
      ['application', 'xslt+xml', 1],
      ['image', 'bmp', 0],
      ['message', 'rfc822', 0],
      ['message', 'x-unknown', 0],
      ['x-unknown', 'x-unknown', 0],
      ['application', 'xhtml+xml', 1],
      ['model', 'x-unknown', 0],
      ['image', 'svg+xml', 1],
      ['application', 'octet-stream', 0],
      ['text', 'x-unknown', 0],
      ['video', 'x-unknown+xml', 1],
      ['text', 'xml', 1],
      ['application', 'xml', 1],
      ['multipart', 'mixed', 0],
      ['multipart', 'example', 0],
      ['unknown', 'unknown+XML', 1],
      ['TEXT', 'XML', 1],
      ['audio', 'xml', 0],
      ['message', 'mime+xml', 1],
      ['text', 'csv+xml+html', 0],
      ['text+xml', 'plain', 0],
  ) {
    my $mt = Web::MIME::Type->new_from_type_and_subtype ($_->[0], $_->[1]);
    is !!$mt->is_xml_mime_type, !!$_->[2], join ' ', 'xmt', @$_;
  }
  done $c;
} n => 26, name => 'is_xmt';

for my $test (
  ['text/plain', 0, 0],
  ['text/html', 0, 0],
  ['audio/basic', 0, 1],
  ['image/PNG', 1, 0],
  ['image/svg+xml', 1, 0],
  ['application/ogg', 0, 1],
  ['image/gif', 1, 0],
  ['video/mpeg', 0, 1],
  ['application/smil', 0, 0],
) {
  test {
    my $c = shift;
    my $mt = Web::MIME::Type->parse_web_mime_type ($test->[0]);
    is !! $mt->is_image, !! $test->[1], 'is_image';
    is !! $mt->is_audio_or_video, !! $test->[2], 'is_audio_or_video';
    done $c;
  } n => 2, name => $test;
}

## ------ Serialization ------

test {
  my $c = shift;
  my $mt = Web::MIME::Type->new_from_type_and_subtype ('text', 'css');
  is $mt->as_valid_mime_type_with_no_params, 'text/css';
  is $mt->as_valid_mime_type, 'text/css';
  is $mt->mime_type_portion, 'text/css';
  done $c;
} n => 3, name => 'as_valid_1';

test {
  my $c = shift;
  my $mt = Web::MIME::Type->new_from_type_and_subtype ('text', 'css');
  $mt->type ('NOT@TEXT');
  is $mt->as_valid_mime_type_with_no_params, undef;
  is $mt->as_valid_mime_type, undef;
  is $mt->mime_type_portion, 'not@text/css';
  done $c;
} n => 3, name => 'as_valid';

test {
  my $c = shift;
  my $mt = Web::MIME::Type->new_from_type_and_subtype ('text', 'css');
  $mt->type ("\x{4e00}");
  is $mt->as_valid_mime_type_with_no_params, undef;
  is $mt->as_valid_mime_type, undef;
  is $mt->mime_type_portion, "\x{4e00}/css";
  done $c;
} n => 3, name => 'as_valid';

test {
  my $c = shift;
  my $mt = Web::MIME::Type->new_from_type_and_subtype ('text', 'css');
  $mt->type ("a/b");
  is $mt->as_valid_mime_type_with_no_params, undef;
  is $mt->as_valid_mime_type, undef;
  is $mt->mime_type_portion, 'a/b/css';
  done $c;
} n => 3, name => 'as_valid';

test {
  my $c = shift;
  my $mt = Web::MIME::Type->new_from_type_and_subtype ('text', 'css');
  $mt->type ('');
  is $mt->as_valid_mime_type_with_no_params, undef;
  is $mt->as_valid_mime_type, undef;
  is $mt->mime_type_portion, '/css';
  done $c;
} n => 3, name => 'as_valid';

test {
  my $c = shift;
  my $mt = Web::MIME::Type->new_from_type_and_subtype ('text', 'css');
  $mt->subtype ('<NOCSS>');
  is $mt->as_valid_mime_type_with_no_params, undef;
  is $mt->as_valid_mime_type, undef;
  is $mt->mime_type_portion, 'text/<nocss>';
  done $c;
} n => 3, name => 'as_valid';

test {
  my $c = shift;
  my $mt = Web::MIME::Type->new_from_type_and_subtype ('text', 'css');
  $mt->subtype ('');
  is $mt->as_valid_mime_type_with_no_params, undef;
  is $mt->as_valid_mime_type, undef;
  is $mt->mime_type_portion, 'text/';
  done $c;
} n => 3, name => 'as_valid';

test {
  my $c = shift;
  my $mt = Web::MIME::Type->new_from_type_and_subtype ('text', 'css');
  $mt->subtype ("\x{FE00}");
  is $mt->as_valid_mime_type_with_no_params, undef;
  is $mt->as_valid_mime_type, undef;
  is $mt->mime_type_portion, "text/\x{FE00}";
  done $c;
} n => 3, name => 'as_valid';

test {
  my $c = shift;
  my $mt = Web::MIME::Type->new_from_type_and_subtype ('text', 'css');
  $mt->param (abc => 'def');
  is $mt->as_valid_mime_type_with_no_params, 'text/css';
  is $mt->as_valid_mime_type, 'text/css;abc=def';
  is $mt->mime_type_portion, 'text/css';
  done $c;
} n => 3, name => 'as_valid';

test {
  my $c = shift;
  my $mt = Web::MIME::Type->new_from_type_and_subtype ('text', 'css');
  $mt->param (abc => 'def<xxyz>');
  is $mt->as_valid_mime_type_with_no_params, 'text/css';
  is $mt->as_valid_mime_type, 'text/css;abc="def<xxyz>"';
  is $mt->mime_type_portion, 'text/css';
  done $c;
} n => 3, name => 'as_valid';

test {
  my $c = shift;
  my $mt = Web::MIME::Type->new_from_type_and_subtype ('text', 'css');
  $mt->param (abc => 'def');
  $mt->param (xyz => 1);
  is $mt->as_valid_mime_type_with_no_params, 'text/css';
  is $mt->as_valid_mime_type, 'text/css;abc=def;xyz=1';
  done $c;
} n => 2, name => 'as_valid';

test {
  my $c = shift;
  my $mt = Web::MIME::Type->new_from_type_and_subtype ('text', 'css');
  $mt->param (abc => 'def');
  $mt->param (xyz => "\x{4e00}");
  is $mt->as_valid_mime_type_with_no_params, 'text/css';
  is $mt->as_valid_mime_type, undef;
  done $c;
} n => 2, name => 'as_valid';

test {
  my $c = shift;
  my $mt = Web::MIME::Type->new_from_type_and_subtype ('text', 'css');
  $mt->param (abc => 'def');
  $mt->param (xyz => "");
  is $mt->as_valid_mime_type_with_no_params, 'text/css';
  is $mt->as_valid_mime_type, 'text/css;abc=def;xyz=""';
  done $c;
} n => 2, name => 'as_valid';

test {
  my $c = shift;
  my $mt = Web::MIME::Type->new_from_type_and_subtype ('text', 'css');
  $mt->param (abc => 'def');
  $mt->param (abc => 'xyz');
  is $mt->as_valid_mime_type_with_no_params, 'text/css';
  is $mt->as_valid_mime_type, 'text/css;abc=xyz';
  done $c;
} n => 2, name => 'as_valid';

test {
  my $c = shift;
  my $mt = Web::MIME::Type->new_from_type_and_subtype ('text', 'css');
  $mt->param (abc => 'def');
  $mt->param (xyz => "<M");
  is $mt->as_valid_mime_type_with_no_params, 'text/css';
  is $mt->as_valid_mime_type, 'text/css;abc=def;xyz="<M"';
  done $c;
} n => 2, name => 'as_valid';

test {
  my $c = shift;
  my $mt = Web::MIME::Type->new_from_type_and_subtype ('text', 'css');
  $mt->param ("<abc>" => 'def');
  is $mt->as_valid_mime_type_with_no_params, 'text/css';
  is $mt->as_valid_mime_type, undef;
  done $c;
} n => 2, name => 'as_valid';

test {
  my $c = shift;
  my $mt = Web::MIME::Type->new_from_type_and_subtype ('text', 'css');
  $mt->param ("" => 'def');
  is $mt->as_valid_mime_type_with_no_params, 'text/css';
  is $mt->as_valid_mime_type, undef;
  done $c;
} n => 2, name => 'as_valid';

test {
  my $c = shift;
  my $mt = Web::MIME::Type->new_from_type_and_subtype ('text', 'css');
  $mt->param ("\x{5000}" => 'def');
  is $mt->as_valid_mime_type_with_no_params, 'text/css';
  is $mt->as_valid_mime_type, undef;
  done $c;
} n => 2, name => 'as_valid';

test {
  my $c = shift;
  my $mt = Web::MIME::Type->new_from_type_and_subtype ('text', 'css');
  $mt->param (abc => "ab\x0Acd");
  is $mt->as_valid_mime_type_with_no_params, 'text/css';
  is $mt->as_valid_mime_type, qq[text/css;abc="ab\x0Acd"];
  done $c;
} n => 2, name => 'as_valid';

test {
  my $c = shift;
  my $mt = Web::MIME::Type->new_from_type_and_subtype ('text', 'css');
  $mt->param (abc => "\x0D\x0D\x0A");
  is $mt->as_valid_mime_type_with_no_params, 'text/css';
  is $mt->as_valid_mime_type, qq[text/css;abc="\x0D\x0D\x0A"];
  done $c;
} n => 2, name => 'as_valid';

test {
  my $c = shift;
  my $mt = Web::MIME::Type->new_from_type_and_subtype ('text', 'css');
  $mt->param (abc => 'de\"f');
  is $mt->as_valid_mime_type_with_no_params, 'text/css';
  is $mt->as_valid_mime_type, qq[text/css;abc="de\x5C\x5C\x5C"f"];
  done $c;
} n => 2, name => 'as_valid';

test {
  my $c = shift;
  my $mt = Web::MIME::Type->new_from_type_and_subtype ('text', 'css');
  $mt->param (abc => qq[de\x00f]);
  is $mt->as_valid_mime_type_with_no_params, 'text/css';
  is $mt->as_valid_mime_type, qq[text/css;abc="de\x00f"];
  done $c;
} n => 2, name => 'as_valid';

test {
  my $c = shift;
  my $mt = Web::MIME::Type->new_from_type_and_subtype ('text', 'css');
  $mt->param (abc => qq[de\x7Ff]);
  is $mt->as_valid_mime_type_with_no_params, 'text/css';
  is $mt->as_valid_mime_type, qq[text/css;abc="de\x7Ff"];
  done $c;
} n => 2, name => 'as_valid';

test {
  my $c = shift;
  my $mt = Web::MIME::Type->new_from_type_and_subtype ('text', 'css');
  $mt->param (abc => qq[de\xFE\xFFf]);
  is $mt->as_valid_mime_type_with_no_params, 'text/css';
  is $mt->as_valid_mime_type, qq[text/css;abc="de\xFE\xFFf"];
  done $c;
} n => 2, name => 'as_valid';

test {
  my $c = shift;
  my $mt = Web::MIME::Type->new_from_type_and_subtype ('text', 'css');
  $mt->param (xza => q[y]);
  is $mt->as_valid_mime_type, qq[text/css;xza=y];
  $mt->param (abc => q[x]);
  is $mt->as_valid_mime_type, qq[text/css;xza=y;abc=x];
  $mt->param (xza => q[aa]);
  is $mt->as_valid_mime_type, qq[text/css;xza=aa;abc=x];
  done $c;
} n => 3, name => 'as_valid parameter orders';

## ------ Conformance ------

for_each_test (path (__FILE__)->parent->parent->child ('t_deps/tests/mime/type-conformance.dat'), {
  data => {is_prefixed => 1, is_list => 1},
  errors => {is_list => 1},
}, sub {
  my ($test, $opts) = @_;
  
  test {
    my $c = shift;
    my @errors;
    my $onerror = sub {
      my %opt = @_;
      push @errors, join ';',
          $opt{type},
          defined $opt{value} ? $opt{value} : '',
          $opt{level};
    }; # $onerror

    my $data = [@{$test->{data}->[0]}];
    
    my $type = Web::MIME::Type->new_from_type_and_subtype
        (shift @$data, shift @$data);
    while (@$data) {
        $type->param (shift @$data => shift @$data);
    }

    $type->validate ($onerror);
    
    if ($test->{errors}) {
      is join ("\n", sort {$a cmp $b} @errors),
          join ("\n", sort {$a cmp $b} @{$test->{errors}->[0]});
    } else {
      warn qq[No #errors section: ] . join ' ', @{$test->{data}->[0]};
    }
    done $c;
  } n => 1, name => ['validate', $opts->{line_number}, @{$test->{data}->[0]}];
});

run_tests;

## License: Public Domain.
