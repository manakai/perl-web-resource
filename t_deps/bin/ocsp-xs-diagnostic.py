import argparse
from collections import deque
import difflib
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import time

MARKER = 'ocsp-xs-diag-20260915-v1'
TEST = Path('t/Web-Transport-HTTPStream-clientparsing.t')
HELPER = r'''
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
static void ocsp_diag_event(const char *stage, const void *connection, long value)
{
    int saved_errno = errno;
    struct timeval stamp;
    if (getenv("OCSP_XS_DIAG")) {
        if (gettimeofday(&stamp, NULL) != 0) {
            stamp.tv_sec = 0;
            stamp.tv_usec = 0;
        }
        fprintf(stderr, "OCSP_XS %ld.%06ld pid=%ld ssl=%p %s value=%ld\n",
                (long)stamp.tv_sec, (long)stamp.tv_usec, (long)getpid(),
                connection, stage, value);
        fflush(stderr);
    }
    errno = saved_errno;
}
'''
BOOTSTRAP = r'''package OcspDiagnosticBootstrap;
use strict;
use warnings;
BEGIN {
  unshift @INC, $ENV{OCSP_DIAG_LIB}, $ENV{OCSP_DIAG_ARCH};
}
use Net::SSLeay;
use DynaLoader ();
BEGIN {
  die "Wrong Net::SSLeay version\n" unless $Net::SSLeay::VERSION eq '1.96';
  die "Uninstrumented Net::SSLeay loaded\n"
      unless Net::SSLeay->can('ocsp_diagnostic_marker')
      && Net::SSLeay::ocsp_diagnostic_marker() eq 'ocsp-xs-diag-20260915-v1';
  die "TLS library changed during rebuild\n"
      unless Net::SSLeay::SSLeay_version(0) eq $ENV{OCSP_DIAG_SSL_VERSION};
  print STDERR "OCSP_BOOT pid=$$ perl=$^X module=$INC{'Net/SSLeay.pm'}\n";
  print STDERR "OCSP_BOOT shared=$_\n" for @DynaLoader::dl_shared_objects;
}
1;
'''
LEGACY_LOGGER = r'''package Test::TLSDiagnostic;
use strict;
use warnings;
use Time::HiRes ();
my $count = 0;
my $pid = $$;
sub event {
  local $!;
  local $@;
  local $?;
  return unless $ENV{WEB_TRANSPORT_TLS_DIAG};
  eval {
    if ($pid != $$) { $pid = $$; $count = 0; }
    return if $count++ >= 20000;
    my @fields = map {
      my $text = !defined $_ ? '<undef>' : ref $_ ? ref $_ : "$_";
      $text =~ s/([^\x20-\x7e])/sprintf('\\x{%x}', ord $1)/ge;
      $text;
    } @_;
    my $line = sprintf("TLS_DIAG %.6f pid=%d %s\n",
                       Time::HiRes::time(), $$, join(' ', @fields));
    syswrite STDERR, $line;
  };
  return;
}
sub environment { event('environment', $^O, $]); }
1;
'''


def once(text, before, after):
    count = text.count(before)
    if count != 1:
        raise ValueError('Expected one anchor, found %d: %r' % (count, before))
    return text.replace(before, after, 1)


def instrument_xs(source):
    if MARKER in source or 'ocsp_diag_event' in source:
        raise ValueError('XS already instrumented; use the original 1.96 source')
    start = source.index('int tlsext_status_cb_invoke(SSL *ssl, void *arg)\n')
    end = source.index('\nint session_ticket_ext_cb_invoke(', start)
    callback = source[start:end]
    callback = once(callback, '    cb_func = cb_data_advanced_get(ctx,',
                    '    ocsp_diag_event("callback.enter", ssl, 0);\n'
                    '    cb_func = cb_data_advanced_get(ctx,')
    callback = once(callback, '    len = SSL_get_tlsext_status_ocsp_resp(ssl, &p);',
                    '    ocsp_diag_event("get.before", ssl, 0);\n'
                    '    len = SSL_get_tlsext_status_ocsp_resp(ssl, &p);\n'
                    '    ocsp_diag_event("get.after.length", ssl, len);\n'
                    '    ocsp_diag_event("get.after.pointer", ssl, p != NULL);')
    callback = once(callback, '    if (p) ocsp_response = d2i_OCSP_RESPONSE(NULL, &p, len);',
                    '    if (p) {\n'
                    '        ocsp_diag_event("der.before", ssl, len);\n'
                    '        ocsp_response = d2i_OCSP_RESPONSE(NULL, &p, len);\n'
                    '        ocsp_diag_event("der.after.nonnull", ssl, ocsp_response != NULL);\n'
                    '    } else {\n'
                    '        ocsp_diag_event("der.skipped", ssl, len);\n'
                    '    }')
    callback = once(callback, '    nres = call_sv(cb_func, G_SCALAR);',
                    '    ocsp_diag_event("perl.before", ssl, 0);\n'
                    '    nres = call_sv(cb_func, G_SCALAR);\n'
                    '    ocsp_diag_event("perl.after.count", ssl, nres);')
    callback = once(callback, '    if (ocsp_response) OCSP_RESPONSE_free(ocsp_response);',
                    '    ocsp_diag_event("free.before", ssl, ocsp_response != NULL);\n'
                    '    if (ocsp_response) OCSP_RESPONSE_free(ocsp_response);\n'
                    '    ocsp_diag_event("free.after", ssl, 0);')
    callback = once(callback, '    return res;',
                    '    ocsp_diag_event("callback.return", ssl, res);\n    return res;')
    source = source[:start] + callback + source[end:]
    control = '        RETVAL = SSL_ctrl(ssl,SSL_CTRL_SET_TLSEXT_STATUS_REQ_OCSP_RESP,staplelen,(void *)p);'
    source = once(source, control,
                  '        ocsp_diag_event("setter.before.length", ssl, (long)staplelen);\n' +
                  control + '\n        ocsp_diag_event("setter.after.return", ssl, RETVAL);')
    marker = ('const char *\nocsp_diagnostic_marker()\n    CODE:\n'
              '        RETVAL = "' + MARKER + '";\n    OUTPUT:\n        RETVAL\n\n')
    source = once(source, 'int\nSSL_set_tlsext_status_type(',
                  marker + 'int\nSSL_set_tlsext_status_type(')
    return once(source, '#include "XSUB.h"\n', '#include "XSUB.h"\n' + HELPER)


def instrument_test(source):
    source = once(source, 'my @End;\n', 'my $OCSP_DIAG_SELECTED = 0;\nmy @End;\n')
    source = once(source, '  next if $path =~ m{/h2};',
                  "  next unless $path->basename eq 'httpstlsocspstaple.dat';\n"
                  '  next if $path =~ m{/h2};')
    source = once(source, '    my $test = $_[0];\n',
                  '    my $test = $_[0];\n'
                  "    return unless ($test->{name}->[0] // '') eq 'Broken staple';\n"
                  '    $OCSP_DIAG_SELECTED++;\n')
    return once(source, 'Test::Certificates->wait_create_cert;\n',
                'die "No Broken staple case selected\\n" unless $OCSP_DIAG_SELECTED;\n'
                'warn "OCSP_DIAG selected=$OCSP_DIAG_SELECTED\\n";\n'
                'Test::Certificates->wait_create_cert;\n')


def capture(command, destination, cwd=None, env=None, timeout=30):
    with destination.open('wb') as output:
        try:
            result = subprocess.run(command, cwd=cwd, env=env, stdout=output,
                                    stderr=subprocess.STDOUT, timeout=timeout)
            return result.returncode
        except (OSError, subprocess.TimeoutExpired) as error:
            output.write(('\n' + str(error) + '\n').encode())
            return 124 if isinstance(error, subprocess.TimeoutExpired) else 127


def stop_group(group):
    for signum in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(group, signum)
        except ProcessLookupError:
            return
        if signum == signal.SIGTERM:
            time.sleep(1)


def snapshot(directory, group):
    path = directory / 'processes.txt'
    capture(['ps', '-axo', 'pid=,ppid=,pgid=,stat=,command='], path)
    members = []
    for line in path.read_text(errors='replace').splitlines():
        fields = line.split(None, 4)
        if len(fields) >= 3 and fields[0].isdigit() and fields[2] == str(group):
            members.append(fields[0])
    for pid in members[:6]:
        command = (['sample', pid, '1', '-file', str(directory / ('sample-' + pid + '.txt'))]
                   if platform.system() == 'Darwin' else
                   ['ps', '-p', pid, '-o', 'pid,ppid,stat,wchan,comm'])
        capture(command, directory / ('snapshot-' + pid + '.txt'), timeout=5)


def supervise(command, directory, env, timeout, name, cwd=None, samples=False):
    with (directory / name).open('wb') as output:
        process = subprocess.Popen(command, cwd=cwd, env=env, stdout=output,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        try:
            try:
                status = process.wait(timeout=timeout)
                return status if status >= 0 else 128 - status
            except subprocess.TimeoutExpired:
                output.write(b'\nOCSP_DIAG OUTER TIMEOUT\n')
                output.flush()
                if samples:
                    snapshot(directory, process.pid)
                return 124
        finally:
            stop_group(process.pid)
            process.wait(timeout=10)


def relative_path(value):
    path = Path(value)
    if path.is_absolute() or '..' in path.parts:
        raise argparse.ArgumentTypeError('Use a workspace-relative path without ..')
    return path


def report_candidates(directory):
    paths = sorted(Path('local').rglob('SSLeay.xs'))
    configured = sorted({path.parent.resolve() for path in paths
                         if (path.parent / 'Makefile').is_file()})
    archives = sorted(Path('local').rglob('Net-SSLeay-1.96.tar.gz'))
    report = ['configured=%d sources=%d archives=%d' %
              (len(configured), len(paths), len(archives))]
    report += ['configured: ' + str(path) for path in configured]
    report += ['source: ' + str(path) for path in paths]
    report += ['archive: ' + str(path) for path in archives]
    text = '\n'.join(report) + '\n'
    (directory / 'build-candidates.txt').write_text(text)
    print(text, file=sys.stderr)
    return configured, archives


def extract_source(archive, destination):
    if archive.stat().st_size > 64 * 1024 * 1024:
        raise ValueError('Source archive exceeds 64 MiB')
    with tarfile.open(archive, 'r:gz') as package:
        members = package.getmembers()
        if sum(member.size for member in members) > 128 * 1024 * 1024:
            raise ValueError('Expanded source exceeds 128 MiB')
        targets = set()
        for member in members:
            path = Path(member.name)
            if (path.is_absolute() or '..' in path.parts
                    or not (member.isdir() or member.isfile())
                    or path in targets):
                raise ValueError('Unsafe or duplicate archive member: ' + member.name)
            targets.add(path)
        destination.mkdir()
        for member in members:
            target = destination / member.name
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with package.extractfile(member) as source, target.open('wb') as output:
                    shutil.copyfileobj(source, output)
                target.chmod(0o755 if member.mode & 0o111 else 0o644)
    roots = [path.parent for path in destination.rglob('SSLeay.xs')
             if (path.parent / 'Makefile.PL').is_file()]
    if len(roots) != 1:
        raise ValueError('Archive must contain exactly one Net-SSLeay source tree')
    source = roots[0]
    version_file = source / 'lib/Net/SSLeay.pm'
    if not re.search(r"\$VERSION\s*=\s*['\"]1\.96['\"]", version_file.read_text()):
        raise ValueError('Archive does not declare Net::SSLeay 1.96')
    instrument_xs((source / 'SSLeay.xs').read_text())
    return source


def fetch_source(directory):
    url = 'https://codeload.github.com/radiator-software/p5-net-ssleay/tar.gz/refs/tags/1.96'
    archive = directory / 'Net-SSLeay-1.96.tar.gz'
    status = capture(['curl', '--fail', '--location', '--silent', '--show-error',
                      '--proto', '=https', '--proto-redir', '=https',
                      '--connect-timeout', '15', '--max-time', '90',
                      '--max-filesize', str(64 * 1024 * 1024),
                      '--output', str(archive), url], directory / 'download.log', timeout=100)
    if status:
        raise ValueError('Source download failed; see download.log or pass --source-archive')
    (directory / 'source-url.txt').write_text(url + '\n')
    return archive


def prepare_build(args, directory, archives, environment, ssl_version):
    prefix = args.openssl_prefix.resolve()
    if not ((prefix / 'include/openssl/ssl.h').is_file()
            and (prefix / 'bin/openssl').is_file()
            and any((prefix / name).is_dir() for name in ('lib', 'lib64'))):
        raise ValueError('Missing existing TLS installation at %s; specify --openssl-prefix. '
                         'No OpenSSL installation or upgrade is performed.' % args.openssl_prefix)
    status = capture([str(prefix / 'bin/openssl'), 'version'],
                     directory / 'prefix-version.txt', env=environment)
    if status or (directory / 'prefix-version.txt').read_text().strip() != ssl_version:
        raise ValueError('TLS prefix version differs from loaded Net::SSLeay; see prefix-version.txt and baseline.txt')
    archive = args.source_archive
    if archive is None and archives:
        hashes = {hashlib.sha256(path.read_bytes()).hexdigest() for path in archives}
        if len(hashes) != 1:
            raise ValueError('Multiple different cached archives; specify --source-archive')
        archive = archives[0]
    if archive is None:
        if not args.fetch_source:
            raise ValueError('No cached source archive; use --fetch-source or --source-archive')
        archive = fetch_source(directory)
    (directory / 'archive-sha256.txt').write_text(
        hashlib.sha256(archive.read_bytes()).hexdigest() + '  ' + str(archive) + '\n')
    build = extract_source(archive, directory / 'source')
    executable = directory / 'perl-executable.txt'
    status = capture(['./perl', '-MCwd=abs_path', '-e', 'print abs_path($^X), "\\n";'],
                     executable, env=environment)
    perl = executable.read_text().strip()
    if status or not Path(perl).is_absolute() or not Path(perl).is_file():
        raise ValueError('Cannot identify original Perl executable; see perl-executable.txt')
    configure_environment = dict(environment)
    configure_environment['OPENSSL_PREFIX'] = str(prefix)
    configure_environment['PERL_MM_USE_DEFAULT'] = '1'
    (directory / 'prepare-config.json').write_text(json.dumps(
        {'perl': perl, 'OPENSSL_PREFIX': str(prefix), 'archive': str(archive),
         'build': str(build)}, indent=2) + '\n')
    status = supervise([perl, 'Makefile.PL'], directory, configure_environment,
                       120, 'configure.log', cwd=build)
    if status or not (build / 'Makefile').is_file():
        raise ValueError('Makefile.PL failed or produced no Makefile; see configure.log')
    print('Prepared diagnostic build: ' + str(build), file=sys.stderr)
    return build


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--ssleay-build', type=relative_path)
    parser.add_argument('--prepare-build', action='store_true')
    parser.add_argument('--fetch-source', action='store_true')
    parser.add_argument('--source-archive', type=relative_path)
    parser.add_argument('--openssl-prefix', type=relative_path, default=Path('local/common'))
    parser.add_argument('--output', type=relative_path, default=Path('local/ocsp-xs-diagnostic'))
    parser.add_argument('--timeout', type=int, default=180)
    args = parser.parse_args()
    if args.ssleay_build and args.prepare_build:
        parser.error('--ssleay-build and --prepare-build are mutually exclusive')
    if (args.fetch_source or args.source_archive) and not args.prepare_build:
        parser.error('--fetch-source and --source-archive require --prepare-build')
    if args.timeout <= 0:
        parser.error('--timeout must be positive')
    directory = args.output.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    if any(directory.iterdir()):
        parser.error('Output must be empty; use a different --output for each run')
    result = {'phase': 'preflight', 'exit_code': 2}
    originals = {}
    try:
        candidates, archives = report_candidates(directory)
        environment = dict(os.environ)
        environment.pop('PERL5OPT', None)
        baseline = directory / 'baseline.txt'
        status = capture(['./perl', '-MNet::SSLeay', '-e',
                          'print "$Net::SSLeay::VERSION\\n", Net::SSLeay::SSLeay_version(0), "\\n";'],
                         baseline, env=environment)
        lines = baseline.read_text(errors='replace').splitlines()
        if status or len(lines) != 2 or lines[0] != '1.96':
            raise ValueError('Baseline must load Net::SSLeay 1.96; see baseline.txt')
        build = args.ssleay_build
        if args.prepare_build:
            result['phase'] = 'prepare-build'
            build = prepare_build(args, directory, archives, environment, lines[1])
        elif build is None:
            if len(candidates) != 1:
                raise ValueError('Found %d configured build(s). Choose --ssleay-build, or '
                                 'run with --prepare-build --fetch-source in a fresh --output.' % len(candidates))
            build = candidates[0]
        build = build.resolve()
        if not (build / 'Makefile').is_file():
            raise ValueError('A configured Net-SSLeay 1.96 build directory with Makefile is required')
        xs = build / 'SSLeay.xs'
        sources = {xs: xs.read_bytes(), TEST: TEST.read_bytes()}
        updated = {xs: instrument_xs(sources[xs].decode()).encode(),
                   TEST: instrument_test(sources[TEST].decode()).encode()}
        (directory / 'instrumentation.patch').write_text(''.join(
            ''.join(difflib.unified_diff(sources[path].decode().splitlines(True),
                                        updated[path].decode().splitlines(True),
                                        'a/' + path.name, 'b/' + path.name)) for path in sources))
        (directory / 'source-hashes.json').write_text(json.dumps(
            {str(path): hashlib.sha256(data).hexdigest() for path, data in sources.items()}, indent=2))
        capture(['git', 'rev-parse', 'HEAD'], directory / 'commit.txt')
        capture(['./perl', '-V'], directory / 'perl-config.txt')
        originals = sources
        xs.write_bytes(updated[xs])
        result['phase'] = 'build'
        status = supervise(['make'], directory, environment, 600, 'build.log', cwd=build)
        if status:
            result['exit_code'] = status
            return status
        overlay = directory / 'overlay'
        shutil.copytree(build / 'blib/lib', overlay / 'lib')
        shutil.copytree(build / 'blib/arch', overlay / 'arch')
        support = directory / 'support'
        (support / 'Test').mkdir(parents=True)
        (support / 'OcspDiagnosticBootstrap.pm').write_text(BOOTSTRAP)
        (support / 'Test/TLSDiagnostic.pm').write_text(LEGACY_LOGGER)
        paths = [str(support), str(overlay / 'lib'), str(overlay / 'arch'),
                 str(Path('t_deps/lib').resolve()), str(Path('lib').resolve())]
        if environment.get('PERL5LIB'):
            paths.append(environment['PERL5LIB'])
        environment['PERL5LIB'] = os.pathsep.join(paths)
        environment['OCSP_DIAG_LIB'] = str(overlay / 'lib')
        environment['OCSP_DIAG_ARCH'] = str(overlay / 'arch')
        environment['PERL5OPT'] = '-MOcspDiagnosticBootstrap'
        environment['OCSP_XS_DIAG'] = '1'
        environment['WEB_TRANSPORT_TLS_DIAG'] = '1'
        environment['OCSP_DIAG_SSL_VERSION'] = lines[1]
        result['phase'] = 'verify-loaded-xs'
        status = capture(['./perl', '-e', 'print "instrumented XS loaded\\n";'],
                         directory / 'loaded-xs.txt', env=environment)
        if status:
            result['exit_code'] = status
            return status
        for shared in (overlay / 'arch').rglob('*'):
            if shared.suffix in ('.so', '.bundle', '.dylib'):
                capture(['otool', '-L', str(shared)] if platform.system() == 'Darwin'
                        else ['ldd', str(shared)], directory / ('linked-' + shared.name + '.txt'))
        TEST.write_bytes(updated[TEST])
        result['phase'] = 'syntax'
        status = capture(['./perl', '-Ilib', '-It_deps/lib', '-c', str(TEST)],
                         directory / 'syntax.txt', env=environment, timeout=45)
        if status:
            result['exit_code'] = status
            return status
        result['phase'] = 'test'
        status = supervise(['./prove', '-v', str(TEST)], directory, environment,
                           args.timeout, 'test.log', samples=True)
        result['exit_code'] = status
        return status
    except (OSError, ValueError) as error:
        (directory / 'error.txt').write_text(str(error) + '\n')
        print(error, file=sys.stderr)
        return 2
    finally:
        for path, data in originals.items():
            path.write_bytes(data)
        (directory / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
        print('OCSP diagnostic phase=%s exit_code=%s' %
              (result['phase'], result['exit_code']), file=sys.stderr)
        for name in ('error.txt', 'test.log', 'syntax.txt', 'loaded-xs.txt', 'build.log', 'configure.log', 'download.log'):
            path = directory / name
            if path.is_file():
                with path.open(errors='replace') as logfile:
                    tail = deque(logfile, maxlen=120)
                print('OCSP diagnostic tail: ' + name, file=sys.stderr)
                print(''.join(tail), file=sys.stderr)
                break
        print('OCSP diagnostic artifacts: ' + str(args.output), file=sys.stderr)


if __name__ == '__main__':
    sys.exit(main())
