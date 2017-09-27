all: build

WGET = wget
GIT = git
PERL = ./perl

updatenightly: local/bin/pmbp.pl clean build
	$(CURL) -f -l https://gist.githubusercontent.com/wakaba/34a71d3137a52abb562d/raw/gistfile1.txt | sh
	git add modules t_deps/modules
	perl local/bin/pmbp.pl --update
	git add config lib/

clean:
	rm -fr local/*.json

## ------ Setup ------

deps: git-submodules pmbp-install

git-submodules:
	$(GIT) submodule update --init

PMBP_OPTIONS =

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

build-main: lib/Web/MIME/_TypeDefs.pm lib/Web/Transport/_Defs.pm

lib/Web/MIME/_TypeDefs.pm: bin/generate-list.pl local/mime-types.json \
    local/mime-sniffing.json
	$(PERL) $< > $@
local/mime-types.json:
	$(WGET) -O $@ https://raw.github.com/manakai/data-web-defs/master/data/mime-types.json
local/mime-sniffing.json:
	$(WGET) -O $@ https://raw.github.com/manakai/data-web-defs/master/data/mime-sniffing.json

lib/Web/Transport/_Defs.pm: bin/generate-transport-defs.pl \
    local/http-status-codes.json local/headers.json
	$(PERL) $< > $@
local/http-status-codes.json:
	$(WGET) -O $@ https://raw.githubusercontent.com/manakai/data-web-defs/master/data/http-status-codes.json
local/headers.json:
	$(WGET) -O $@ https://raw.githubusercontent.com/manakai/data-web-defs/master/data/headers.json

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
	-curl http://localhost:8522/end

test-real: test-deps test-real-main

test-real-main:
	$(PROVE) t/real/*.t

## License: Public Domain.
