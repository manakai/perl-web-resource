all: build

WGET = wget
GIT = git
PERL = ./perl

updatenightly: build
	$(GIT) add lib/Web/MIME/_TypeDefs.pm

clean:
	rm -fr local/mime-types.json

## ------ Setup ------

deps: git-submodules pmbp-install

git-submodules:
	$(GIT) submodule update --init

local/bin/pmbp.pl:
	mkdir -p local/bin
	$(WGET) -O $@ https://raw.github.com/wakaba/perl-setupenv/master/bin/pmbp.pl
pmbp-upgrade: local/bin/pmbp.pl
	perl local/bin/pmbp.pl --update-pmbp-pl
pmbp-update: git-submodules pmbp-upgrade
	perl local/bin/pmbp.pl --update
pmbp-install: pmbp-upgrade
	perl local/bin/pmbp.pl \
	    --install \
            --create-perl-command-shortcut @perl \
            --create-perl-command-shortcut @prove \
	    --create-perl-command-shortcut @openssl

## ------ Build ------

build: build-deps build-main

build-deps: deps

build-main: lib/Web/MIME/_TypeDefs.pm lib/Web/Transport/_Defs.pm

lib/Web/MIME/_TypeDefs.pm: local/mime-types.json bin/generate-list.pl
	$(PERL) bin/generate-list.pl < $< > $@
local/mime-types.json:
	$(WGET) -O $@ https://raw.github.com/manakai/data-web-defs/master/data/mime-types.json

lib/Web/Transport/_Defs.pm: bin/generate-transport-defs.pl \
    local/http-status-codes.json
	$(PERL) $< > $@
local/http-status-codes.json:
	$(WGET) -O $@ https://raw.githubusercontent.com/manakai/data-web-defs/master/data/http-status-codes.json

## ------ Tests ------

PROVE = ./prove

test: test-deps test-main test-main-server

test-deps: deps

test-main:
	$(PROVE) t/*.t
	WEBUA_DEBUG=2 $(PERL) t/Web-Transport-WSClient.t
	TEST_METHOD=37 WEBUA_DEBUG=2 $(PERL) t/Web-Transport-ConnectionClient.t
	TEST_METHOD=45 WEBUA_DEBUG=2 $(PERL) t/Web-Transport-PSGIServerConnection.t

test-main-server:
	$(PERL) sketch/server.pl &
	sleep 1
	$(PROVE) t/httpserver/*.t
	-curl http://localhost:8522/end

## License: Public Domain.
