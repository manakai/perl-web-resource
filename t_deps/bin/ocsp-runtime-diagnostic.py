import argparse
from collections import deque
import difflib
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import time

TEST = Path('t/Web-Transport-HTTPStream-clientparsing.t')
PROBE = r'''package OcspRuntimeProbe;
use strict;
use warnings;
use Time::HiRes ();
my $events = 0;
my $event_pid = $$;
sub event {
  local $!;
  local $@;
  local $?;
  eval {
    if ($event_pid != $$) { $event_pid = $$; $events = 0; }
    return if $events++ >= 20000;
    my @fields = map {
      my $value = !defined $_ ? '<undef>' : ref $_ ? ref $_ : "$_";
      $value =~ s/([^\x20-\x7e])/sprintf('\\x{%x}', ord $1)/ge;
      $value;
    } @_;
    my $line = sprintf("OCSP_RUNTIME %.6f pid=%d %s\n",
                       Time::HiRes::time(), $$, join(' ', @fields));
    syswrite STDERR, $line;
  };
  return;
}
sub install {
  event('bootstrap', $0, 'perl=' . $^X, 'hooks=' . $ENV{OCSP_RUNTIME_HOOKS});
  return unless $ENV{OCSP_RUNTIME_HOOKS} eq 'on';
  require Net::SSLeay;
  require DynaLoader;
  event('library', $Net::SSLeay::VERSION, Net::SSLeay::SSLeay_version(0),
        $INC{'Net/SSLeay.pm'});
  event('shared', $_) for @DynaLoader::dl_shared_objects;
  my $setter = Net::SSLeay->can('set_tlsext_status_ocsp_resp')
      or die "Installed Net::SSLeay lacks OCSP setter\n";
  my $register = Net::SSLeay->can('CTX_set_tlsext_status_cb')
      or die "Installed Net::SSLeay lacks OCSP callback registration\n";
  no warnings 'redefine';
  no strict 'refs';
  *{'Net::SSLeay::set_tlsext_status_ocsp_resp'} = sub {
    event('setter.before', $_[0], defined $_[1] ? length($_[1]) : '<undef>');
    my $result = $setter->(@_);
    event('setter.return', $_[0], $result);
    return $result;
  };
  *{'Net::SSLeay::CTX_set_tlsext_status_cb'} = sub {
    my @arguments = @_;
    my $callback = $arguments[1];
    if (ref $callback eq 'CODE') {
      $arguments[1] = sub {
        event('callback.enter', $_[0], $_[1] ? 'response' : 'no-response');
        my $result = $callback->(@_);
        event('callback.return', $_[0], $result);
        return $result;
      };
    }
    event('register.before', $arguments[0]);
    my $result = $register->(@arguments);
    event('register.return', $arguments[0], $result);
    return $result;
  };
  event('hooks.installed');
}
package Test::TLSDiagnostic;
sub event { goto &OcspRuntimeProbe::event; }
sub environment { OcspRuntimeProbe::event('environment', $^O, $]); }
$INC{'Test/TLSDiagnostic.pm'} = __FILE__;
package OcspRuntimeProbe;
install();
1;
'''


def once(text, before, after):
    count = text.count(before)
    if count != 1:
        raise ValueError('Expected one test anchor, found %d: %r' % (count, before))
    return text.replace(before, after, 1)


def select_test(source):
    source = once(source, 'my @End;\n', 'my $OCSP_RUNTIME_SELECTED = 0;\nmy @End;\n')
    source = once(source, '  next if $path =~ m{/h2};',
                  "  next unless $path->basename eq 'httpstlsocspstaple.dat';\n"
                  '  next if $path =~ m{/h2};')
    source = once(source, '    my $test = $_[0];\n',
                  '    my $test = $_[0];\n'
                  "    return unless ($test->{name}->[0] // '') eq 'Broken staple';\n"
                  '    $OCSP_RUNTIME_SELECTED++;\n')
    return once(source, 'Test::Certificates->wait_create_cert;\n',
                'die "No Broken staple selected\\n" unless $OCSP_RUNTIME_SELECTED;\n'
                'warn "OCSP_RUNTIME selected=$OCSP_RUNTIME_SELECTED\\n";\n'
                'Test::Certificates->wait_create_cert;\n')


def capture(command, destination, environment=None, timeout=5):
    with destination.open('wb') as output:
        try:
            return subprocess.run(command, stdout=output, stderr=subprocess.STDOUT,
                                  env=environment, timeout=timeout).returncode
        except (OSError, subprocess.TimeoutExpired) as error:
            output.write((str(error) + '\n').encode())
            return 124 if isinstance(error, subprocess.TimeoutExpired) else 127


def snapshot(directory, group):
    directory.mkdir()
    processes = directory / 'processes.txt'
    capture(['ps', '-axo', 'pid=,ppid=,pgid=,stat=,command='], processes)
    rows = []
    for line in processes.read_text(errors='replace').splitlines():
        fields = line.split(None, 4)
        if len(fields) == 5 and all(field.isdigit() for field in fields[:3]):
            rows.append(fields)
    descendants = {str(group)}
    while True:
        expanded = descendants | {fields[0] for fields in rows
                                  if fields[1] in descendants or fields[2] == str(group)}
        if expanded == descendants:
            break
        descendants = expanded
    members = [fields for fields in rows if fields[0] in descendants]
    members.sort(key=lambda fields: ('perl' not in fields[4].lower(), fields[0] == str(group)))
    statuses = {}
    for fields in members[:6]:
        pid = fields[0]
        command = (['sample', pid, '1', '-file', str(directory / ('sample-' + pid + '.txt'))]
                   if platform.system() == 'Darwin' else
                   ['ps', '-p', pid, '-o', 'pid,ppid,stat,wchan,comm'])
        statuses[pid] = capture(command, directory / ('collector-' + pid + '.txt'))
    (directory / 'collection.json').write_text(json.dumps(statuses, indent=2) + '\n')


def stop_group(group):
    for signum in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(group, signum)
        except ProcessLookupError:
            return
        if signum == signal.SIGTERM:
            time.sleep(1)


def supervise(command, directory, environment, sample_after, timeout):
    with (directory / 'test.log').open('wb') as output:
        process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT,
                                   env=environment, start_new_session=True)
        deadline = time.monotonic() + timeout
        try:
            try:
                status = process.wait(timeout=sample_after)
            except subprocess.TimeoutExpired:
                print('Collecting early snapshot before the test timeout', file=sys.stderr)
                snapshot(directory / 'early-snapshot', process.pid)
                try:
                    status = process.wait(timeout=max(0, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    output.write(b'\nOCSP_RUNTIME outer timeout\n')
                    output.flush()
                    return 124
            return status if status >= 0 else 128 - status
        finally:
            stop_group(process.pid)
            process.wait(timeout=10)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--hooks', choices=['on', 'off'], default='on')
    parser.add_argument('--sample-after', type=int, default=30)
    parser.add_argument('--timeout', type=int, default=180)
    parser.add_argument('--output', default='local/ocsp-runtime-diagnostic')
    args = parser.parse_args()
    if not 0 < args.sample_after < args.timeout:
        parser.error('require 0 < sample-after < timeout')
    directory = Path(args.output)
    if directory.is_absolute() or '..' in directory.parts:
        parser.error('--output must be workspace-relative without ..')
    directory.mkdir(parents=True, exist_ok=True)
    if any(directory.iterdir()):
        parser.error('output must be empty; use a different --output')
    result = {'phase': 'preflight', 'exit_code': 2}
    originals = {}
    try:
        server = Path('t_deps/server.pl')
        sources = {path: path.read_bytes() for path in (TEST, server)}
        bootstrap = 'BEGIN { require $ENV{OCSP_RUNTIME_PROBE}; }\n'
        selected = {
            TEST: (bootstrap + select_test(sources[TEST].decode())).encode(),
            server: bootstrap.encode() + sources[server],
        }
        support = directory / 'support'
        support.mkdir()
        (support / 'OcspRuntimeProbe.pm').write_text(PROBE)
        environment = dict(os.environ)
        if 'OcspDiagnosticBootstrap' in environment.get('PERL5OPT', ''):
            raise ValueError('Remove the XS diagnostic PERL5OPT before running this independent probe')
        environment['OCSP_RUNTIME_PROBE'] = str((support / 'OcspRuntimeProbe.pm').resolve())
        environment['OCSP_RUNTIME_HOOKS'] = args.hooks
        capture(['git', 'rev-parse', 'HEAD'], directory / 'commit.txt')
        result['exit_code'] = capture(['./perl', '-e', bootstrap + 'print "probe ready\\n";'],
                                     directory / 'probe-load.txt', environment, 30)
        if result['exit_code']:
            return result['exit_code']
        (directory / 'test-selection.patch').write_text(''.join(
            ''.join(difflib.unified_diff(sources[path].decode().splitlines(True),
                                        selected[path].decode().splitlines(True),
                                        'a/' + str(path), 'b/' + str(path)))
            for path in sources))
        originals = sources
        for path, content in selected.items():
            path.write_bytes(content)
        result['phase'] = 'syntax'
        result['exit_code'] = capture(['./perl', '-Ilib', '-It_deps/lib', '-c', str(TEST)],
                                     directory / 'syntax.txt', environment, 30)
        if result['exit_code']:
            return result['exit_code']
        result['phase'] = 'test'
        result['exit_code'] = supervise(['./prove', '-v', str(TEST)], directory,
                                       environment, args.sample_after, args.timeout)
        return result['exit_code']
    except (OSError, ValueError) as error:
        result['exit_code'] = 2
        (directory / 'error.txt').write_text(str(error) + '\n')
        return 2
    finally:
        for path, content in originals.items():
            path.write_bytes(content)
        (directory / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
        print('OCSP runtime phase=%s exit_code=%s' %
              (result['phase'], result['exit_code']), file=sys.stderr)
        for name in ('error.txt', 'test.log', 'syntax.txt', 'probe-load.txt'):
            path = directory / name
            if path.is_file():
                with path.open(errors='replace') as logfile:
                    print(''.join(deque(logfile, maxlen=100)), file=sys.stderr)
                break
        print('Artifacts: ' + str(directory), file=sys.stderr)


if __name__ == '__main__':
    sys.exit(main())
