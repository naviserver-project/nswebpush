package require uri

#
# Test file for VAPID token generation
# RFC 8292: Voluntary Application Server Identification (VAPID)
#

set ::vapidCertPath "[ns_info home]/modules/vapid"
set ::testSuite "[ns_info home]/pages/pushnotificationsapi/TestSuite.tcl"

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
    exec -ignorestderr openssl ec -in prime256v1_key.pem -pubout -outform DER | tail -c 65 | base64 | tr -d '=' | tr '/+' '-_' > public_key.txt
    exec -ignorestderr openssl ec -in prime256v1_key.pem -outform DER | tail -c +8 | head -c 32 | base64 | tr -d '=' | tr '/+' '-_' > private_key.txt
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
#
# timeout is the timeout parameter of the push message (post request)
#
# ttl is the time to live of the push message
proc webpush {subscription data claim private_key_pem {timeout 2.0} {ttl 0}} {
  # validate subscription
  if {[dict exists $subscription endpoint]} {
      set endpoint [dict get $subscription endpoint]
  } else {
    error "No endpoint information provided!"
  }
  # validate private key and create public key in base64url encoded format
  set server_public_key [ns_crypto::eckey pub -pem $private_key_pem -encoding base64url]
  # validate/fill claim
  set claim [validateClaim $claim $endpoint]
  # create a signed jwt token
  set jwt [makeJWT $claim $private_key_pem]
  # create vapid Authorization header
  set authorization "WebPush $jwt"
  # the crypto key header contains the server public key
  set cryptokey p256ecdsa=$server_public_key
  # start creating headers
  set headers [ns_set create]
  ns_set update $headers Authorization $authorization
  ns_set update $headers Crypto-Key $cryptokey
  ns_set update $headers TTL $ttl
  # data bearing push messages need "auth" and "p256dh" fields for encryption
  if {$data ne {}} {
    if {![dict exists $subscription auth] || ![dict exists $subscription p256dh]} {
      error "Data bearing push messages need auth and p256dh fields in subscription"
    }
    # for each data bearing push messages a new local private key needs to be created
    set localPrivateKeyPem [createPrivateKeyPem $::vapidCertPath/temp_encryption_priv.pem]
    set localPubKey [ns_crypto::eckey pub -pem $localPrivateKeyPem -encoding base64url]
    # public key used for encryption needs to be appended to the crypt-key header.
    # The keyid field links the Crypto-Key header with the Encryption header.
    # It is not strictly required, but some push services may expect it.
    append cryptokey ";dh=$localPubKey;keyid=p256dh"
    ns_set update $headers Crypto-Key $cryptokey
    # the Encryption header contains the salt which is a 16 byte (128bit) random value
    # also used for encryption encoded in base64url format
    set randomBits {}
    for {set i 0} {$i < 128} {incr i} {
      append randomBits [ns_rand 2]
    }
    set salt [binary format b128 $randomBits]
    set encryption "keyid=p256dh;salt=[ns_base64urlencode $salt]"
    ns_set update $headers Encryption $encryption
    # set content-encoding and content-type headers
    ns_set update $headers Content-Encoding aesgcm
    ns_set update $headers Content-Type application/octet-stream
    # encrypt the data
    set encrData [encrypt $data \
                          $localPrivateKeyPem \
                          [ns_base64urldecode [dict get $subscription auth]] \
                          [ns_base64urldecode [dict get $subscription p256dh]] \
                          $salt]
    # content-length header is the length of the encrypted data in bytes
    ns_set update $headers Content-Length [string length $encrData]
    # queue the request
    set req [ns_http queue -method POST \
       -headers $headers \
       -timeout $timeout \
       -body $encrData \
       $endpoint]
  } else {
    # push messages without a payload do not have a request body
    set req [ns_http queue -method POST \
       -headers $headers \
       -timeout $timeout \
       $endpoint]
  }
  set replyHeaders [ns_set create]
  # wait for answer of push service and record reply
  ns_http wait -result result -headers $replyHeaders -status status $req
  puts $result
  puts $status
  if {$status > 202} {
    error "Webpush failed!" $result $status
  }
  return $status
}
# creates a new EC private key pem file at the given location
# overwrites the file if it exists
# returns the path if successfull
proc createPrivateKeyPem {path} {
  if {[file exists $path]} {
    file delete -force $path
  }
  ns_crypto::eckey generate -name prime256v1 -pem $path
  return $path
}

# creates a public key pem file at the location specified in path
# derived from the private key pem file specified in privkey
# overwrites the file if it exists
# returns the path if successfull
proc createPublicKeyPem {path privkey} {
  if {[file exists $path]} {
    file delete -force $path
  }
  if {[catch {
    exec -ignorestderr openssl ec -in $privkey -pubout -out $path
  }]} {
    error "Could not generate public key"
  }
  return $path
}
#
# validates the contents of a claim and fills the "aud" and "exp" fields if not present
# validates the "aud" field against the endpoint
# set the "exp" field to a correct value if it is wrong
#
# returns a valid claim as a dict or throws an exception
proc validateClaim {claim endpoint} {
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
  } else {
    dict set claim exp [expr [clock seconds] + 59*60*24]
  }
  return $claim
}

# takes a claim and the path to an EC private key and creates a
# signed JWT token
# whitespaces and newlines are stripped from the claim
proc makeJWT {claim private_key_pem} {
  # this is always the jwt header
  set JWTHeader [ns_base64urlencode {{"typ":"JWT","alg":"ES256"}}]
  # reformat claim dict to json
  set JWTbody [ns_base64urlencode [dictToJson $claim]]

  set signature [::ns_crypto::md vapidsign -digest sha256\
   -encoding base64url -pem $private_key_pem $JWTHeader.$JWTbody ]
  return $JWTHeader.$JWTbody.$signature
}
# generate the key/nonce info according to specification from the
# clients public key and servers private key
# type should be 'aesgcm' or 'nonce'
# keys are expected in binary format
#
# returns info in binary format
proc generateInfo {type clientPubKey serverPubKey} {
  set info [binary format A18 "Content-Encoding: "]
  append info [binary format A* $type]
  append info [binary format x]
  append info [binary format A5 "P-256"]
  append info [binary format x]
  # length of keys are 65 bytes for webpush
  append info [binary format S1 65]
  append info $clientPubKey
  append info [binary format S1 65]
  append info $serverPubKey

  return $info
}
# derives key and nonce from client public key, server public key, initial key material and salt
# input parameters are expected in binary encoding
# returns the encryption key and nonce in binary for webpush as a list (first element key, 2nd nonce)
proc createEncryptionKeyNonce {clientPubKey serverPubKey ikm salt} {
  set keyInfo [generateInfo aesgcm $clientPubKey $serverPubKey]
  set key [ns_crypto::md hkdf -digest sha256 -salt $salt -secret $ikm -info $keyInfo -encoding binary 16]

  set nonceInfo [generateInfo nonce $clientPubKey $serverPubKey]
  set nonce [ns_crypto::md hkdf -digest sha256 -salt $salt -secret $ikm -info $nonceInfo -encoding binary 12]

  return [list $key $nonce]
}
# encrypts the data using a private key from a pem file, the auth and p256dh fields of a subscription
# and a 16 byte random salt value
# aesgcm encoding for webpush is used
# privKeyPem is the path to an EC private key pem file
# other parameters are expected in binary format
#
# returns the encrypted message in binary format
proc encrypt {data privKeyPem auth p256dh salt} {
  set ServerPubKey [ns_crypto::eckey pub -pem $privKeyPem -encoding binary]
  # puts "serverpubkey [ns_base64encode $ServerPubKey]"
  set sharedSecret [ns_crypto::eckey sharedsecret -pem $privKeyPem -encoding binary $p256dh]
  #puts "sharedSecret [ns_base64encode $sharedSecret]"
  # make initial key material
  set authInfo [binary format A*x "Content-Encoding: auth"]
  #puts "authinfo [ns_base64encode $authInfo]"
  set ikm [ns_crypto::md hkdf -digest sha256 \
             -salt   $auth \
             -secret $sharedSecret \
             -info   $authInfo \
             -encoding binary \
              32]
  #puts "ikm [ns_base64encode $ikm]"
  # create encryption key and nonce
  set keyNonce [createEncryptionKeyNonce $p256dh $ServerPubKey $ikm $salt]
  set key [lindex $keyNonce 0]
  #puts "key [ns_base64encode $key]"
  set nonce [lindex $keyNonce 1]
  #puts "nonce [ns_base64encode $nonce]"
  # do encryption
  set cipher [::ns_crypto::enc string -cipher aes-128-gcm -iv $nonce -key $key $data]
  set result [dict get $cipher bytes][dict get $cipher tag]
  return [binary format H* $result]
}
# serializes a dict to json
# no testing for nested dicts or arrays, these will be simply added as a string
# the json is in compact form,
# meaning no whitespaces and newlines between keys/values
proc dictToJson {dict} {
  set retJson "{"
  dict for {key value} $dict {
    append retJson [subst {"$key":"$value",}]
  }
  return [string range $retJson 0 end-1]}
}




set claim [subst {
  {
  "sub" : "mailto:h0325904@wu.ac.at",
  "aud" : "https://updates.push.services.mozilla.com/",
  "exp" : "[expr [clock seconds] + 60*120]"
  }
}]

# the JWT base string is the header and body separated with a "."
set JWTHeader [ns_base64urlencode {{"typ":"JWT","alg":"ES256"}}]
set JWTbody [ns_base64urlencode [stripWhitespacesNewlines $claim]]

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

source $::testSuite

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
