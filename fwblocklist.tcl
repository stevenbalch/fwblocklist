#!/usr/bin/tclsh

#-----------------------------------------
# fwblocklist -- 1.00
# Utility to block an IP list based on quota
# Created by Steven W. Balch Jr.
#-----------------------------------------

set timer 3600

#-----------------------------------------
puts ""
puts "Starting FW Blocklist Process"
puts ""
puts "Enabling DoS mitigation for quota"
puts ""
exec sim_dos ctl -a 1 -m 0 -x 0 -l 100

set url [lindex $argv 0]
#-----------------------------------------

#-----------------------------------------
if {$url == ""} {
puts {}
puts { -- It looks like you are missing the source URL IP list -- }
puts {}
exit
                }
#-----------------------------------------

#-----------------------------------------
proc curlist {} {
global url entry timer

if [catch {set clist [exec curl -s --cacert /opt/CPshrd-R77/conf/ca-bundle.crt --retry 10 --retry-delay 60 $url]} err] {
puts $err
} else {
#puts $clist
set cn 0
foreach entry $clist {
#puts $entry

# This is where you need to add more input validation
if {[regexp "^#" $entry] == 1} {
#skip
                               }
#puts $entry
lappend dyraw "add -a d -l r -t $timer quota service any source range:$entry pkt-rate 0 flush true\n"
incr cn
                     }
#puts $dyraw
        }
lappend dyraw "add -t 2 quota flush true"

regsub -all "\} \{" $dyraw "" dyraw
regsub -all "\{" $dyraw "" dyraw
regsub -all "\}" $dyraw "" dyraw
exec cat /dev/null > .active
exec echo $dyraw >> .active
puts "Blocking a total of: $cn unique IP addresses"
#puts "$dyraw"
exec -keepnewline fw samp batch < .active
                 }
#-----------------------------------------

#-----------------------------------------
curlist
#-----------------------------------------
puts ""
puts "Finished FW Blocklist Process"
#-----------------------------------------

