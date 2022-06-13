#
# Simple configuration file for testing of the nswebpush Tcl module
#

set homedir [pwd]/tests
set bindir  [file dirname [ns_info nsd]]

ns_section "ns/parameters"
ns_param   home           $homedir
ns_param   tcllibrary     $bindir/../tcl
ns_param   logdebug       false

ns_section "ns/servers"
ns_param   test            "Test Server"

ns_section "ns/server/test/tcl"
ns_param   initfile        $bindir/init.tcl
ns_param   library         $homedir/modules

ns_section "ns/server/test/modules"
ns_param   nswebpush        tcl

