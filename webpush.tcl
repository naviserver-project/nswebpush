package require uri
package require nsf

namespace eval webpush {
    #
    #  webpush::send
    #
    nsf::proc send {
	-subscription
	-data
	-claim
	-privateKeyPem
	-localKeyPath
	{-mode aesgcm}
	{-timeout 2.0}
	{-ttl 0}
    } {
	#
	#  Send a push notification to the specified substription endpoint
	#
	# @param subscription is expected to be a dict that includes
	# at least an "endpoint" for data bearing subscriptions an
	# "auth" and a "p256dh" fields are expected (these fields
	# should expect the base64url encoded values) claim is a dict
	# containing at least a field that contains a
	# "mailto:example@example.org" email address the "aud" of the
	# claim will be extracted from the endpoint if not provided
	# "exp" will be set to +24hours from the time of the function
	# call if not provided
	#
	# @param privateKeyPem is the path to a pem file containing
	#        a VAPID EC private key
	#
	# @pram localKeyPath is a path to a directory with write
	#       access to create temporary keys for encryption
	#
	# @param mode can be either 'aesgcm' or 'aes128gcm'
	#
	# @param timeout is the timeout parameter of the push message
	#        (POST request)
	#
	# @param ttl is the time to live of the push message

	if {$mode ni {aesgcm aes128gcm}} {
	    error "Unknown GCM mode"
	}
	# validate subscription
	if {[dict exists $subscription endpoint]} {
	    set endpoint [dict get $subscription endpoint]
	} else {
	    error "No endpoint information provided!"
	}

	#
	# validate private key and create public key in base64url
	# encoded format
	#
	set server_public_key [ns_crypto::eckey pub -pem $privateKeyPem -encoding base64url]

	#
	# validate/fill claim
	#
	set claim [validateClaim $claim $endpoint]

	#
	# create a signed jwt token
	#
	set jwt [makeJWT $claim $privateKeyPem]

	#
	# create vapid Authorization header
	#
	set authorization "vapid t=$jwt,k=$server_public_key"

	#
	# start creating headers
	#
	set headers [ns_set create]
	ns_set update $headers "authorization" $authorization
	ns_set update $headers "ttl" $ttl

	#
	# data bearing push messages need "auth" and "p256dh" fields
	# for encryption
	#
	if {$data ne {}} {
	    if {![dict exists $subscription auth]
		|| ![dict exists $subscription p256dh]
	    } {
		error "Data bearing push messages need auth and p256dh fields in subscription"
	    }

	    #
	    # For each data bearing push messages a new local private
	    # key needs to be created.
	    #
	    set localPrivateKeyPem [createPrivateKeyPem $localKeyPath/temp_encryption_priv.pem]
	    set localPubKey [ns_crypto::eckey pub -pem $localPrivateKeyPem -encoding base64url]

	    #
	    # salt is needed for encryption.
	    #
	    set salt [ns_crypto::randombytes -encoding binary 16]
	    if {$mode eq "aesgcm"} {
		#
		# public key used for encryption needs to be appended
		# to the crypt-key header.  The keyid field links the
		# Crypto-Key header with the Encryption header.  It is
		# not strictly required, but some push services may
		# expect it.
		#
		set cryptokey "dh=$localPubKey;keyid=p256dh"
		ns_set update $headers "crypto-key" $cryptokey

		#
		# The encryption header contains the salt also used
		# for encryption encoded in base64url format.
		#
		set encryption "keyid=p256dh;salt=[ns_base64urlencode $salt]"
		ns_set update $headers "encryption" $encryption
	    }

	    #
	    # Set content-encoding and content-type headers.
	    #
	    ns_set update $headers "content-encoding" $mode
	    ns_set update $headers "content-type" application/octet-stream

	    #
	    # encrypt the data
	    #
	    set encrData [encrypt \
			      -data $data \
			      -privateKeyPem $localPrivateKeyPem \
			      -auth [ns_base64urldecode [dict get $subscription auth]] \
			      -p256dh [ns_base64urldecode [dict get $subscription p256dh]] \
			      -salt $salt \
			      -mode $mode]
	    #
	    # content-length header is the length of the encrypted data in bytes
	    #
	    ns_set update $headers "content-length" [string length $encrData]

	    #
	    # queue the request
	    #
	    set req [ns_http queue -method POST \
			 -headers $headers \
			 -timeout $timeout \
			 -body $encrData \
			 $endpoint]
	} else {
	    ns_set update $headers "content-type" "application/octet-stream"
	    #
	    # Push messages without a payload do not have a request body
	    #
	    set req [ns_http queue -method POST \
			 -headers $headers \
			 -timeout $timeout \
			 -body "" \
			 $endpoint]
	}
	set replyHeaders [ns_set create]
	#
	# wait for answer of push service and record reply
	#
	ns_http wait -result result -headers $replyHeaders -status status $req
	if {$status > 202} {
	    error "Webpush failed!" $result $status
	}
	return $status
    }

    proc createPrivateKeyPem {path} {
	#
	# Creates a new EC private key pem file at the given location
	# overwrites the file if it exists
	# returns the path if successful
	#
	if {[file exists $path]} {
	    file delete -force $path
	}
	ns_crypto::eckey generate -name prime256v1 -pem $path
	return $path
    }

    proc validateClaim {claim endpoint} {
	#
	# Validates the contents of a claim and fills the "aud" and
	# "exp" fields if not present validates the "aud" field
	# against the endpoint set the "exp" field to a correct value
	# if it is wrong
	#
	# @return a valid claim as a dict or throws an exception

	#
	# validate 'sub'
	#
	if {[dict exists $claim sub]} {
	    set mail [::uri::split [dict get $claim sub]]
	    if {[dict get $mail scheme] ne "mailto"} {
		error "'sub' must be of form 'mailto:...@...'"
	    }
	} else {
	    error "claim must contain 'sub'"
	}

	#
	# validate/add 'aud'
	#
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
		set aud [::uri::join scheme $endPointArr(scheme) host $endPointArr(host)]
		# remove / at the end of url
		dict set claim aud [string range $aud 0 end-1]
	    } else {
		set aud [::uri::join scheme $endPointArr(scheme) host $endPointArr(host) port $endPointArr(port)]
		# remove / at the end of url
		dict set claim aud [string range $aud 0 end-1]
	    }
	}

	#
	# validate/add exp
	#
	if {[dict exists $claim exp]} {
	    set exp [dict get $claim exp]
	    if {
		![string is integer $exp]
		|| ($exp < [clock seconds])
		|| ($exp > ([clock seconds] + 60*60*24))
	    } {
		dict set claim exp [expr {[clock seconds] + 59*60*24}]
	    }
	} else {
	    dict set claim exp [expr {[clock seconds] + 59*60*24}]
	}
	return $claim
    }

    proc makeJWT {claim privateKeyPem} {
	#
	# Take a claim and the path to an EC private key and creates
	# a signed JWT token. Whitespace and newlines are stripped
	# from the claim.
	#

	# this is always the jwt header
	set JWTHeader [ns_base64urlencode {{"typ":"JWT","alg":"ES256"}}]
	# reformat claim dict to json
	set JWTbody [ns_base64urlencode [dictToJson $claim]]

	set signature [::ns_crypto::md vapidsign \
			   -digest sha256 \
			   -encoding base64url \
			   -pem $privateKeyPem \
			   $JWTHeader.$JWTbody ]

	return $JWTHeader.$JWTbody.$signature
    }

    proc generateInfo {type clientPubKey serverPubKey} {
	#
	# Generate the key/nonce info according to specification from
	# the clients public key and servers private key type should
	# be 'aesgcm', 'aes128gcm' or 'nonce' keys are expected in
	# binary format.
	#
	# @return info in binary format

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


    proc createEncryptionKeyNonce {clientPubKey serverPubKey ikm salt mode} {
	#
	# Derive key and nonce from client public key, server public
	# key, initial key material and salt input parameters (except
	# mode which can be 'aesgcm' or 'aes128gcm') are expected
	# in binary encoding returns the encryption key and nonce in
	# binary for webpush as a list (first element key, 2nd nonce)

	if {$mode eq "aes128gcm"} {
	    set keyInfo [binary format A*x "Content-Encoding: aes128gcm"]
	    set nonceInfo [binary format A*x "Content-Encoding: nonce"]
	} else {
	    set keyInfo [generateInfo aesgcm $clientPubKey $serverPubKey]
	    set nonceInfo [generateInfo nonce $clientPubKey $serverPubKey]
	}

	set key [ns_crypto::md hkdf -digest sha256 -salt $salt -secret $ikm -info $keyInfo -encoding binary 16]
	set nonce [ns_crypto::md hkdf -digest sha256 -salt $salt -secret $ikm -info $nonceInfo -encoding binary 12]

	return [list $key $nonce]
    }


    proc makeIkm {auth p256dh ServerPubKey sharedSecret mode} {
	#
	# Create the initial key material for Web Push the specified
	# mode.
	#
	if {$mode eq "aes128gcm"} {
	    set authInfo [binary format A*x "WebPush: info"]
	    append authInfo $p256dh
	    append authInfo $ServerPubKey
	} else {
	    set authInfo [binary format A*x "Content-Encoding: auth"]
	}
	return [ns_crypto::md hkdf -digest sha256 \
		    -salt   $auth \
		    -secret $sharedSecret \
		    -info   $authInfo \
		    -encoding binary \
		    32]
    }

    proc padData {mode data} {
	#
	# Fill the data with maximum padding according to the mode
	# returns the padded data.
	#

	if {$mode eq "aesgcm"} {
	    #
	    # maximum size for aesgcm is 4078
	    #
	    set paddingLength [expr {4078 - [string bytelength $data]}]

	    #
	    # The first two bytes of the padding indicate how many
	    # bytes of padding follow the padding itself consists of
	    # NULL bytes.
	    set padding [binary format Sx$paddingLength $paddingLength]
	    return $padding$data

	} elseif {$mode eq "aes128gcm"} {
	    #
	    # Set maximum padding length: maximum lengt(4096 - 86 for
	    # header) - 16 for the cipher tag - 1 for the delimiter
	    # byte.
	    #
	    set paddingLength [expr {4010 - 16 - 1 - [string bytelength $data]}]
	    set padding \x02
	    append padding [binary format x$paddingLength]
	    return $data$padding

	} else {
	    error "Unknown GCM mode $mode. Only aesgcm and aes128gcm are supported"
	}
    }

    proc createAes128gcmHeader {salt publicKey} {
	#
	# Create the encryption content encoding header according to
	# aes128gcm draft.  Parameters are expected in binary format.

	set result $salt
	#
	# Set record size to maximum for now.
	#
	append result [binary format I 4096]
	append result [binary format c [string length $publicKey]]
	append result $publicKey
	return $result
    }

    nsf::proc encrypt {
      -data
      -privateKeyPem
      -auth
      -p256dh
      -salt
      -mode
    } {
	#
	# Encrypt the data using a private key from a pem file, the
	# auth and p256dh fields of a subscription and a 16 byte
	# random salt value.
	#
	# @param privateKeyPem is the path to an EC private key pem file
	# @param mode can be 'aesgcm' or 'aes128gcm'
	#
	# other parameters are expected in binary format.
	#
	# @return the encrypted message in binary format

	if {[string bytelength $data] > 4078} {
	    error "data is too large, maximum is 4078 bytes!"
	}
	set serverPubKey [ns_crypto::eckey pub -pem $privateKeyPem -encoding binary]
	set sharedSecret [ns_crypto::eckey sharedsecret -pem $privateKeyPem -encoding binary $p256dh]

	#
	# Make initial key material.
	#
	set ikm [makeIkm $auth $p256dh $serverPubKey $sharedSecret $mode]

	#
	# Create encryption key and nonce
	#
	set keyNonce [createEncryptionKeyNonce $p256dh $serverPubKey $ikm $salt $mode]
	set key [lindex $keyNonce 0]
	set nonce [lindex $keyNonce 1]

	#
	# Do encryption:
	#
	set paddedData [padData $mode $data]
	set cipher [::ns_crypto::aead::encrypt string -cipher aes-128-gcm -iv $nonce -key $key -encoding binary $paddedData]

	#
	# aes128gcm requires the header to be sent in the payload
	#
	set result {}
	if {$mode eq "aes128gcm"} {
	    set result [createAes128gcmHeader $salt $serverPubKey]
	}
	append result [dict get $cipher bytes][dict get $cipher tag]
	return $result
    }

    proc extractHeader {bytes} {
	#
	# Extract the key material and salt according to aes128gcm.
	#
	# @return a list containing the key then the salt then the
	# total length of the header.
	#

	# salt are the first 16 bytes
	set salt [string range $bytes 0 15]

	#
	# the length of the key material is set in byte 21
	#
	binary scan [string index $bytes 20] c len
	set key [string range $bytes 21 [expr {20 + $len}]]
	set headerlen [expr {16 + 4 + 1 + $len}]
	return [list $key $salt $headerlen]
    }

    proc unpad {data mode} {
	#
	# Unpad data according to the mode.
	#
	if {$mode eq "aesgcm"} {
	    #
	    # Padding consists of leading null bytes followed by two
	    # bytes that indicate the size of the padding.
	    #
	    # CHECK: bei diesem unpadden können potentiell auch nullen
	    # gelöscht werden, die nicht Bestandteil des paddings
	    # sind. Richtig wäre: umwandeln der letzten beiden bytes
	    # in die Länge (n), dann Löschen der letzten n Bytes.
	    #
	    # Remove the 2 bytes of padding length.
	    #
	    set data [string range $data 2 end]
	    #
	    # Remove null bytes (padding) from the left.
	    #
	    return [string trimleft $data "\x00"]

	} elseif {$mode eq "aes128gcm"} {
	    #
	    # Remove Null bytes at the end are padding.
	    #
	    set data [string trimright $data "\x00"]
	    #
	    # One delimiter bytes separates the data and the padding
	    # remove this byte
	    #
	    return [string range $data 0 end-1]
	}
    }

    nsf::proc decrypt {
      -encrData
      -privateKeyPem
      -auth
      -mode
      {-serverPubKey ""}
      {-salt ""}
    } {
	#
	# Decrypt the encrypted data using a private key from a pem
	# file, the server public key, the auth secret and a 16 byte
	# random salt value. Removes any padding after decryption.
	# The private key must be the key from the keypair that was
	# used for encryption (p256dh field in the subscription info
	# is the public key). The public key of server and salt can be
	# derived from the ciphertext (encrData) in aes128gcm.
	#
	# @param mode can be 'aesgcm' or 'aes128gcm'
	# other parameters (including data) are expected in binary format
	#
	# @param return the encrypted message in binary format
	#
	if {$serverPubKey eq "" || $salt eq ""} {
	    if {$mode ne "aes128gcm"} {
		error "Server public key and salt required for $mode GCM mode!"
	    }
	    # get key and salt from header
	    set keySalt [extractHeader $encrData]
	    set serverPubKey [lindex $keySalt 0]
	    set salt [lindex $keySalt 1]
	    # remove header
	    set headerlen [lindex $keySalt 2]
	    set encrData [string range $encrData $headerlen end]
	}
	set sharedSecret [ns_crypto::eckey sharedsecret \
			      -pem $privateKeyPem \
			      -encoding binary \
			      $serverPubKey]

	#
	# make initial key material
	#
	set localPub [ns_crypto::eckey pub -pem $privateKeyPem -encoding binary]
	set ikm [makeIkm $auth $localPub $serverPubKey $sharedSecret $mode]

	#
	# create encryption key and nonce
	#
	set keyNonce [createEncryptionKeyNonce $localPub $serverPubKey $ikm $salt $mode]
	set key [lindex $keyNonce 0]
	set nonce [lindex $keyNonce 1]

	#
	# the tag are the last 16 bytes of the data
	#
	set tag [string range $encrData end-15 end]
	set data [string range $encrData 0 end-16]

	set decrypted [ns_crypto::aead::decrypt string \
			   -cipher aes-128-gcm \
			   -iv $nonce \
			   -key $key \
			   -tag $tag \
			   -encoding binary \
			   $data]

	return [unpad $decrypted $mode]
    }

  proc dictToJson {dict} {
  #
  # Serializes a dict to JSON.  no testing for nested dicts or
  # arrays, these will be simply added as a string the json is
  # in compact form, meaning no whitespaces and newlines between
  # keys/values.

  set retJson "{"
  dict for {key value} $dict {
    append retJson [subst {"$key":"$value",}]
  }
  return "[string range $retJson 0 end-1]}"
    }


}
