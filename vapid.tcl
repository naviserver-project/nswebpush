package require ::json::write

#from http://wiki.tcl.tk/40053
proc dict2json {dictToEncode} {
    ::json::write object {*}[dict map {k v} $dictToEncode {
        set v [::json::write string $v]
    }]
}

set claims [dict create]
dict set claims "sub" "mailto:h0325904@wu.ac.at"
dict set claims "aud" "https://fcm.googleapis.com"
dict set claims "exp" [expr [clock seconds] + 60*120]

::json::write indented false
set claims [dict2json $claims]

# url save base64 encoding replaces "/" with "_" and removes "="
set JWTbody [string map {= ""} [string map {/ _} [binary encode base64 $claims]]]
