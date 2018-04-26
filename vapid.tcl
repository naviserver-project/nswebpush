set ::vapidCertPath "[ns_info home]/modules//usr/local/ns/modules/vapid"
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
    exec -ignorestderr  openssl ec -in prime256v1_key.pem -pubout -outform DER | tail -c 65 | base64 | tr -d '=' | tr '/+' '_-' > public_key.txt
    exec -ignorestderr openssl ec -in prime256v1_key.pem -outform DER | tail -c +8 | head -c 32 | base64 | tr -d '=' | tr '/+' '_-' > private_key.txt
}

# url save base64 encoding replaces "/" with "_", "+" with "-" and removes "=" and newlines
proc base64url {data} {
  return [string map {+ - / _ = {} \n {}} [ns_base64encode $data]]
}

proc decodebase64url {data} {
  return [encoding convertto utf-8 [binary decode base64 [string map {- + _ /} $data]]
}

proc stripWhitespacesNewlines {str} {
  return [string map {" " {} \n {}} $str]
}

proc vapidToken {string} {
    set hexSignature [::ns_crypto::md vapidsign -digest sha256 -pem $::vapidCertPath/prime256v1_key.pem $string]
    return $string.[base64url [binary format H* $hexSignature]]
}


set claim [subst {
  {
  "sub" : "mailto:h0325904@wu.ac.at",
  "aud" : "https://updates.push.services.mozilla.com",
  "exp" : "[expr [clock seconds] + 60*120]"
  }
}]


# this is always the jwt header
set JWTHeader [base64url {{"typ":"JWT","alg":"ES256"}}]
puts [stripWhitespacesNewlines $claim]
set JWTbody [base64url [stripWhitespacesNewlines $claim]]

# the JWT base string is the header and body separated with a "."
set token [vapidToken $JWTHeader.$JWTbody]
ns_log notice "VAPID token: <$token>"

set f [open $::vapidCertPath/public_key.txt]
set pub_key [read $f]
close $f

set f [open $::vapidCertPath/public.pem]
set pub_pem [read $f]
close $f

ns_return 200 text/plain [subst {
    claim:
    $claim

    VAPID token: <$token>

    $::vapidCertPath/prime256v1_key.pem - [file size $::vapidCertPath/prime256v1_key.pem] bytes
    $::vapidCertPath/public_key.txt     - [file size $::vapidCertPath/public_key.txt] bytes
    $::vapidCertPath/private_key.txt    - [file size $::vapidCertPath/private_key.txt] bytes

    public_key:
    $pub_key

    public.pem:
    $pub_pem

    HOME: $::env(HOME)
}]
