package require tcltest
package require uri

#
# Test file for VAPID token generation
# RFC 8292: Voluntary Application Server Identification (VAPID)
#

set ::vapidCertPath "[ns_info home]/modules/vapid"

if {![file exists $::vapidCertPath/prime256v1_key.pem]} {
    #
    # create private key for vapid
    #
    if {[catch {
	file mkdir $::vapidCertPath
    }]} {
	ns_log notice "insufficient permissions for NaviServer to crate directory $::vapidCertPath"
	ns_log notice "probably the following command will help:\nsudo chown nsadmin [ns_info home]/modules/"
    } else {
	cd $::vapidCertPath
	ns_log notice ".... creating private_key.pem"
	exec -ignorestderr openssl ecparam -genkey -name prime256v1 -out prime256v1_key.pem
    }
}
if {![file exists $::vapidCertPath/public_key.txt]} {
    cd $::vapidCertPath
    ns_log notice ".... extracting .txt files"
    exec -ignorestderr openssl ec -in prime256v1_key.pem -pubout -outform DER | tail -c 65 | base64 | tr -d '=' | tr '/+' '_-' > public_key.txt
    exec -ignorestderr openssl ec -in prime256v1_key.pem -outform DER | tail -c +8 | head -c 32 | base64 | tr -d '=' | tr '/+' '_-' > private_key.txt
}

proc stripWhitespacesNewlines {str} {
  return [string map {" " {} \n {}} $str]
}

proc vapidToken {string} {
    set signature [::ns_crypto::md vapidsign -digest sha256 -encoding base64url -pem $::vapidCertPath/prime256v1_key.pem $string]
    return $string.$signature
}

#
#  webpush
#
#  send a push notification to the specified substription endpoint
#
#  subscribtion is expected to be a dict that includes at least an "endpoint"
#  for data bearing subscriptions the key field needs to be set aswell
#  this is an example of a json formatted subscribtion:
# {
#   "endpoint":"https://updates.push.services.mozilla.com/wpush/v2/gAAAA...",
#   "keys":{
#     "auth":"5DqpICDCHSi..",
#     "p256dh":"BFECk9GdfDOJOzx.."
#   }
# }
#
# claim is a dict containing at least a "sub" field that contains a "mailto:example@example.org" email adress
# the "aud" of the claim will be extracted from the endpoint if not provided
# "exp" will be set to +24hours from the time of the function call if not provided
#
# private_key is the path to a pem file containing a VAPID EC private key
proc webpush {subscription data claim private_key} {
  puts webpush
  puts [subst  {"subscr: $subscription"}]
  puts [subst  {"data: $data"}]
  puts [subst  {"claim: $claim"}]
  puts [subst  {"privatekey: $private_key"}]

  if {[dict exists $subscription endpoint]} {
      set endpoint [dict get $subscription endpoint]
  } else {
    error "No endpoint information provided!"
  }
  set $claim [validateClaim $claim $endpoint]
}
#
# validates the contents of a claim and fills the "aud" and "exp" fields if not present
# validates the "aud" field against the endpoint
# set the "exp" field to a correct value if it is wrong
#
# returns a valid claim as a dict or throws an exception
proc validateClaim {claim endpoint} {
  puts validateClaim
  puts [subst {"claim: $claim"}]
  puts [subst {"endpoint: $endpoint"}]
  # validate 'sub'
  if {[dict exists $claim sub]} {
    set mail [::uri::split [dict get $claim sub]]
    if {[dict get $mail scheme] ne "mailto"} {
      error "'sub' must be of form 'mailto:...@...'"
    }
  } else {
    error "claim must contain 'sub'"
  }
  # validate/add 'aud'
  array set endPointArr [::uri::split $endpoint]
  if {[dict exists $claim aud]} {
    array set aud [::uri::split [dict get $claim aud]]
    if {
      $endPointArr(scheme) ne $aud(scheme) ||
      $endPointArr(host) ne $aud(host) ||
      $endPointArr(port) ne $aud(port)
      } {
      error "'aud' of claim does not match endpoint"
    }
  } else {
    if {$endPointArr(port) eq ""} {
      dict set claim aud [::uri::join scheme $endPointArr(scheme) host $endPointArr(host)]
    } else {
      dict set claim aud [::uri::join scheme $endPointArr(scheme) host $endPointArr(host) port $endPointArr(port)]
    }
  }
  # validate/add exp
  if {[dict exists $claim exp]} {
    set exp [dict get $claim exp]
    if {
      ![string is integer $exp] ||
      [expr $exp < [clock seconds]] ||
      [expr $exp > ([clock seconds] + 60*60*24)]} {
      dict set claim exp [expr [clock seconds] + 59*60*24]
    }
  }
  return $claim
}


set claim [subst {
  {
  "sub" : "mailto:h0325904@wu.ac.at",
  "aud" : "https://updates.push.services.mozilla.com",
  "exp" : "[expr [clock seconds] + 60*120]"
  }
}]


# this is always the jwt header
set JWTHeader [ns_base64urlencode {{"typ":"JWT","alg":"ES256"}}]
puts [stripWhitespacesNewlines $claim]
set JWTbody [ns_base64urlencode [stripWhitespacesNewlines $claim]]

# the JWT base string is the header and body separated with a "."
set token [vapidToken $JWTHeader.$JWTbody]
ns_log notice "VAPID token: <$token>"

set f [open $::vapidCertPath/public_key.txt]
set pub_key [read $f]
close $f

set f [open $::vapidCertPath/private_key.txt]
set priv_key [read $f]
close $f

set f [open $::vapidCertPath/prime256v1_key.pem]
set pem [read $f]
close $f

namespace eval ::Test {
    namespace import ::tcltest::*

    # check if "exp" is correctly replaced
    test validateClaim {} -body {
      set validMail {mailto:georg@test.com}
      # this is only a valid formatting, the endpoint does not exist
      set validEndpoint "https://updates.push.services.mozilla.com/wpush/v2/gAAAAABa6CXAoHisP"

      set claim [validateClaim [subst {sub $validMail exp 12345}] $validEndpoint]
      set exp [dict get $claim exp]
      set result [expr [clock seconds] < $exp && $exp < [expr [clock seconds] + 60*61*24]]

      set claim [validateClaim [subst {sub $validMail exp [expr [clock seconds] + 60*60*27]}] $validEndpoint]
      set exp [dict get $claim exp]
      append result [expr [clock seconds] < $exp && $exp < [expr [clock seconds] + 60*61*24]]
      set aud [dict get $claim aud]
      if {$aud eq "https://updates.push.services.mozilla.com/"} {
        append result 1
      }
    } -result {111}

    test webpush-exceptions {} -body {
      set validMail {mailto:georg@test.com}
      # this is only a valid formatting, the endpoint does not exist
      set validEndpoint {endpoint https://updates.push.services.mozilla.com/wpush/v2/gAAAAABa6CXAoHisP}
      set validPem $::vapidCertPath/prime256v1_key.pem

      # all wrong
      set result [catch {webpush a "" "" ""}]
      # missing private key
      append result [catch {webpush $validEndpoint "" [subst {sub $validMail}] ""}]
      # invalid email adress
      append result [catch {webpush $validEndpoint "" {sub mailto:test@test} $validPem}]
      # endpoint and 'aud' missmatch
      append result [catch {webpush $validEndpoint "" [subst {sub $validMail aud "abc"}] $validPem}]
    } -result {1111}

    test webpush-cannotconnect {} -body {
      set validMail {mailto:georg@test.com}
      # this is only a valid formatting, the endpoint does not exist
      set validEndpoint {endpoint https://updates.push.services.mozilla.com/wpush/v2/gAAAAABa6CXAoHisP}
      set validPem $::vapidCertPath/prime256v1_key.pem
      # all good (no data is ok) - expected result is error 404 cannot connect
      catch {webpush $validEndpoint "" [subst {sub $validMail}] $validPem} msg opt
      set result [dict get $opt -errorcode]
      # all good (valid aud)
      catch {webpush $validEndpoint "" [subst {sub $validMail aud "https://updates.push.services.mozilla.com/"}] $validPem} msg opt
      append result [dict get $opt -errorcode]
      # all good (valid exp)
      catch {webpush $validEndpoint "" [subst {sub $validMail exp [expr [clock seconds] + 60*120]}] $validPem} msg opt
      append result [dict get $opt -errorcode]
    } -result {404404404}
    cleanupTests
}
namespace delete ::Test


ns_return 200 text/plain [subst {
    claim:
    $claim

    unsigned: $JWTHeader.$JWTbody

    VAPID token: $token
    VAPID token length: [string length $token]

    $::vapidCertPath/prime256v1_key.pem - [file size $::vapidCertPath/prime256v1_key.pem] bytes
    $::vapidCertPath/public_key.txt     - [file size $::vapidCertPath/public_key.txt] bytes
    $::vapidCertPath/private_key.txt    - [file size $::vapidCertPath/private_key.txt] bytes

    public_key : [string trim $pub_key]
    private_key: [string trim $priv_key]

    prime256v1_key.pem\n$pem

    HOME: $::env(HOME)
}]
