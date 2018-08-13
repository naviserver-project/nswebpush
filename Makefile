#
# Support for multiple NaviServer installations on a single host
#
ifndef NAVISERVER
    NAVISERVER  = /usr/local/ns
endif

#
# Allow to specify the modules directory.
# Default: plain NaviServer installation: /usr/local/ns/modules/tcl
#
ifndef MODULEDIR
    MODULEDIR = $(DESTDIR)$(INSTTCL)
endif

#
# Allow to specify a place for installing the webpush demo.
# Default: plain NaviServer installation: /usr/local/ns/pages/
#

ifndef DEMODIR
    DEMODIR = $(DESTDIR)$(INSTSRVPAG)
endif


#
# Name of the modules
#
MODNAME = nswebpush

#
# List of components to be installed as the the Tcl module section
#
TCL =	webpush-procs.tcl \
	README

#
# Get the common Makefile rules
#
include  $(NAVISERVER)/include/Makefile.module

LD_LIBRARY_PATH = LD_LIBRARY_PATH="./:$$LD_LIBRARY_PATH"
NSD             = $(NAVISERVER)/bin/nsd
NS_TEST_CFG     = -c -d -t tests/config.tcl -u nsadmin
NS_TEST_ALL     = all.tcl $(TESTFLAGS)

test: all
	export $(LD_LIBRARY_PATH); $(NSD) $(NS_TEST_CFG) $(NS_TEST_ALL)

install: $(TCL)
	@$(MKDIR) $(MODULEDIR)/$(MODNAME)
	for t in $(TCL); do \
		$(INSTALL_DATA) $$t $(MODULEDIR)/$(MODNAME)/; \
	done

DEMOFILES = \
	demo/Report.html demo/index.tcl demo/webpush-demo.tcl \
	demo/prime256v1_key.pem demo/sw.js demo/webpush.js demo/index.css \
	demo/webpush-send.png demo/webpush-subscribe.png

install-demo:
	@$(MKDIR) $(DEMODIR)/webpush-demo
	@chmod 755 $(DEMODIR)/webpush-demo
	@for i in $(DEMOFILES) ; do \
		$(INSTALL_DATA) $$i $(DEMODIR)/webpush-demo; \
	done
	chown -R nsadmin:nsadmin $(DEMODIR)/webpush-demo
