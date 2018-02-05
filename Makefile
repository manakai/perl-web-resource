all: build

WGET = wget
CURL = curl
GIT = git
PERL = ./perl

updatenightly: clean build
	$(GIT) add lib/Web/MIME/_TypeDefs.pm

clean:
	rm -fr local/mime-types.json lib/Web/Transport/JSON.pm
	rm -fr intermediate/parsing-errors.json

## ------ Setup ------

deps: git-submodules pmbp-install

git-submodules:
	$(GIT) submodule update --init

local/bin/pmbp.pl:
	mkdir -p local/bin
	$(WGET) -O $@ https://raw.github.com/wakaba/perl-setupenv/master/bin/pmbp.pl
pmbp-upgrade: local/bin/pmbp.pl
	perl local/bin/pmbp.pl $(PMBP_OPTIONS) --update-pmbp-pl
pmbp-update: git-submodules pmbp-upgrade
	perl local/bin/pmbp.pl $(PMBP_OPTIONS) --update
pmbp-install: pmbp-upgrade
	perl local/bin/pmbp.pl $(PMBP_OPTIONS) \
	    --install \
            --create-perl-command-shortcut @perl \
            --create-perl-command-shortcut @prove \
	    --create-perl-command-shortcut @openssl

## ------ Build ------

build: build-deps build-main

build-deps: deps

build-main: lib/Web/MIME/_TypeDefs.pm lib/Web/Transport/_Defs.pm \
    lib/Web/Transport/JSON.pm intermediate/parsing-errors.json

lib/Web/MIME/_TypeDefs.pm: bin/generate-list.pl local/mime-types.json \
    local/mime-sniffing.json
	$(PERL) $< > $@
local/mime-types.json:
	$(WGET) -O $@ https://raw.github.com/manakai/data-web-defs/master/data/mime-types.json
local/mime-sniffing.json:
	$(WGET) -O $@ https://raw.github.com/manakai/data-web-defs/master/data/mime-sniffing.json

lib/Web/Transport/_Defs.pm: bin/generate-transport-defs.pl \
    local/http-status-codes.json
	$(PERL) $< > $@
local/http-status-codes.json:
	$(WGET) -O $@ https://raw.githubusercontent.com/manakai/data-web-defs/master/data/http-status-codes.json

lib/Web/Transport/JSON.pm:
	$(CURL) -S -L -f https://raw.githubusercontent.com/wakaba/perl-json-ps/master/lib/JSON/PS.pm | \
	    sed -e 's/JSON::PS/Web::Transport::JSON/g' | \
	    sed -e 's/perl2json_bytes/_UNUSED1/g' | \
	    sed -e 's/json_bytes2perl/_UNUSED2/g' | \
	    sed -e 's/file2perl/_UNUSED3/g' > $@
	$(PERL) -c $@

intermediate/parsing-errors.json: bin/generate-errors.pl src/parsing-errors.txt
	$(PERL) $< src/parsing-errors.txt > $@

## ------ Tests ------

PROVE = ./prove

test: test-deps test-main test-real-main

test-deps: deps

test-main: test-main-main test-main-server

test-main-main:
	$(PROVE) t/*.t

test-main-server:
	$(PERL) t_deps/bin/rawserver.pl &
	sleep 1
	$(PERL) t/httpserver/client.t http://localhost:8522
	-$(CURL) http://localhost:8522/end

test-real: test-deps test-real-main

test-real-main:
	$(PROVE) t/real/*.t

## License: Public Domain.
