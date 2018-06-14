package require tcltest
package require json

namespace eval ::Test {
    namespace import ::tcltest::*

    test dictToJson {} -body {
      # key and value of json are supposed to be quoted
      set d [dict create a b 1 4]
      set result [dictToJson $d]
      set d [dict create "a" b 1 "4"]
      append result [dictToJson $d]
      # whitespaces in keys/values should stay
      set d [dict create "a 1" a b "b 2"]
      append result [dictToJson $d]
    } -result {{"a":"b","1":"4"}{"a":"b","1":"4"}{"a 1":"a","b":"b 2"}}

    test validateClaim {} -body {
      set validMail {mailto:georg@test.com}
      # this is only a valid formatting, the endpoint does not exist
      set validEndpoint "https://updates.push.services.mozilla.com/wpush/v2/gAAAAABa6CXAoHisP"

      set claim [validateClaim [subst {sub $validMail exp 12345}] $validEndpoint]
      set exp [dict get $claim exp]
      set result [expr [clock seconds] < $exp && $exp < [expr [clock seconds] + 60*61*24]]

      set claim [validateClaim [subst {sub $validMail}] $validEndpoint]
      if {![catch {dict get $claim exp}]} {
        append result 1
      }

      set claim [validateClaim [subst {sub $validMail exp [expr [clock seconds] + 60*60*27]}] $validEndpoint]
      set exp [dict get $claim exp]
      append result [expr [clock seconds] < $exp && $exp < [expr [clock seconds] + 60*61*24]]
      set aud [dict get $claim aud]
      if {$aud eq "https://updates.push.services.mozilla.com/"} {
        append result 1
      }
      # endpoint and 'aud' missmatch
      append result [catch {validateClaim [subst {sub $validMail aud "abc"}] $validEndpoint}]
    } -result {11111}

    test webpush-exceptions {} -body {
      set validMail {mailto:georg@test.com}
      # this is only a valid formatting, the endpoint does not exist
      set validEndpoint {endpoint https://updates.push.services.mozilla.com/wpush/v2/gAAAAABa6CXAoHisP}
      set validPem $::vapidCertPath/prime256v1_key.pem

      # all wrong
      set result [catch {webpush a "" "" ""}]
      # missing private key
      append result [catch {webpush $validEndpoint "" [subst {sub $validMail}] ""}]
      # private key not a pem file
      append result [catch {webpush $validEndpoint "" [subst {sub $validMail}] $::vapidCertPath/public_key.txt}]
      # invalid email adress
      append result [catch {webpush $validEndpoint "" {sub maito:testtest} $validPem}]
      # auth and p256dh missing in subscription for data bearing Webpush
      append result [catch {webpush $validEndpoint "testdata" [subst {sub $validMail}] $validPem}]
      # invalid Encoding
      append result [catch {webpush $validEndpoint "" [subst {sub $validMail}] $validPem abcencoding}]
    } -result {111111}
    # positive tests fro parameter formating
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

    test webpush-success {} -body {
      set epDict [::json::json2dict {
        {"endpoint":"https://updates.push.services.mozilla.com/wpush/v2/gAAAAABbDva6eH834SujdvM_jCvKNhk3j5qycsmjqy--oatro7xbySC-zS83JoKdIPLoxgwZAb3mS3gamJGqQVyOH6XEDujnT8dPqBoohOwLycnQ5JvYB2TGBAoipOz8ftH0w1g5-7nti6jstuEBnMcnjraC3PcnXo-GYwyRnp3Tf-0DHdccZQI","keys":{"auth":"nkWlfrXfEbDqEeLVVwo4rw","p256dh":"BMovGyGsKqOeLFsThvtoDm3NgtKSVyVqyeoIoASqhlkd46Ei6BSJa3codWCjpdG46UiYvKPAXAi8c2Y2WKT81yU"}}
        }]
      set keys [dict get $epDict keys]
      set validEndpoint [subst {endpoint [dict get $epDict endpoint] auth [dict get $keys auth] p256dh [dict get $keys p256dh]}]
      set validClaim {sub mailto:georg@test.com}
      set validPem $::vapidCertPath/prime256v1_key.pem
      if {[webpush $validEndpoint "" $validClaim $validPem aesgcm 60] < 300} {
        set result 1
      }
      if {[webpush $validEndpoint "encrypted data received!" $validClaim $validPem aesgcm 60] < 300} {
        append result 1
      }
      if {[webpush $validEndpoint "encrypted data received!" $validClaim $validPem aes128gcm 60] < 300} {
        append result 1
      }
    } -result {111}

    test createPrivateKeyPem {} -body {
      createPrivateKeyPem $::vapidCertPath/localpriv.pem
      if {[file exists $::vapidCertPath/localpriv.pem]} {
        set result 1
      }
    } -result {1}

    test createPublicKeyPem {} -body {
      set privkey [createPrivateKeyPem $::vapidCertPath/localpriv.pem]
      createPublicKeyPem $::vapidCertPath/localpub.pem $privkey
      if {[file exists $::vapidCertPath/localpub.pem]} {
        set result 1
      }
    } -result {1}

    # input/output for encryption functions from node.js crypto library
    # see "test.js"
    test generateInfo {} -body {
      set result [string map {"\n" {}} [ns_base64encode \
        [generateInfo aesgcm [ns_base64urldecode BJkXi48PlCiNCs9dLggxXQ39bdi64agt_emycss5gsg5BYqOWwP5gnbmga7Rg1_tKvnu0c3InK0C850s1czzyBg] [ns_base64urldecode BJZRgas6kMag9rP2X5oVVhGzPwwT24p103WKkPlB7jFTmYVA3QsuLBaSSxNO-UVU-0SjHo0uIsiNoFQRYLDt7cE]]]]
    } -result {Q29udGVudC1FbmNvZGluZzogYWVzZ2NtAFAtMjU2AABBBJkXi48PlCiNCs9dLggxXQ39bdi64agt/emycss5gsg5BYqOWwP5gnbmga7Rg1/tKvnu0c3InK0C850s1czzyBgAQQSWUYGrOpDGoPaz9l+aFVYRsz8ME9uKddN1ipD5Qe4xU5mFQN0LLiwWkksTTvlFVPtEox6NLiLIjaBUEWCw7e3B}

    test createEncryptionKeyNonce {} -body {
      set clientPubKey [ns_base64decode BNvOAPaPCCfpNCMR4AccTffxD8YMQbfIBWieLxgZE1qgU+YVVT5mOD7CaRRqg5ykA7/f8jm2VuOPZLvHn0moHas=]
      set serverPubKey [ns_base64decode BFzhXP5G5Pp5xmEfESPsd7L6N2oQZZypGd2tUR5diW9spzJFs5DXaUuM1iMVfZGunUhtHkyYjqPfcQ2bfzKzbeY=]
      set ikm [ns_base64decode 4qL0g1tKiepxN01MPiRVjDAgC8PWwjlpFNccAS5rtvo=]
      set salt [ns_base64decode WVGtEt/7tGKMNgqAeDvEPA==]
      set keynonce [createEncryptionKeyNonce $clientPubKey \
        $serverPubKey \
        $ikm \
        $salt \
        aesgcm]
      set key [lindex $keynonce 0]
      set nonce [lindex $keynonce 1]
      set result [ns_base64encode $key]
      concat $result [ns_base64encode $nonce]
    } -result {bwUz6s4vfAi5a9xGFBVRXg== n14o2v4+edg7+ggO}

    test encrypt {} -body {
      set result [string map {"\n" {}} [ns_base64encode [encrypt "Push notification payload!" \
        $::vapidCertPath/prime256v1_key.pem \
        [ns_base64urldecode 4LLU4S9l1S9IrPTsQZkPqw] \
        [ns_base64urldecode BNvOAPaPCCfpNCMR4AccTffxD8YMQbfIBWieLxgZE1qgU-YVVT5mOD7CaRRqg5ykA7_f8jm2VuOPZLvHn0moHas] \
        [ns_base64decode WVGtEt/7tGKMNgqAeDvEPA==] \
        aesgcm]]]

      set tooLong {}
      while {[string bytelength $tooLong] < 4079} {
        append tooLong A
      }
      append result [catch {[encrypt $tooLong \
        $::vapidCertPath/prime256v1_key.pem \
        [ns_base64urldecode 4LLU4S9l1S9IrPTsQZkPqw] \
        [ns_base64urldecode BNvOAPaPCCfpNCMR4AccTffxD8YMQbfIBWieLxgZE1qgU-YVVT5mOD7CaRRqg5ykA7_f8jm2VuOPZLvHn0moHas] \
        [ns_base64decode WVGtEt/7tGKMNgqAeDvEPA==]]}]
    } -result {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1}

    test decrypt {} -body {
      # this is the client keypair
      set localPriv [createPrivateKeyPem $::vapidCertPath/localpriv.pem]
      set localPub [ns_crypto::eckey pub -pem $::vapidCertPath/localpriv.pem -encoding binary]
      # client public key i ś the p256dh field in a subscription
      set encrypted [encrypt "Encryptiontest" \
        $::vapidCertPath/prime256v1_key.pem \
        [ns_base64urldecode 4LLU4S9l1S9IrPTsQZkPqw] \
        $localPub \
        [ns_base64decode WVGtEt/7tGKMNgqAeDvEPA==] \
        aesgcm]

      set ServerPubKey [ns_crypto::eckey pub -pem $::vapidCertPath/prime256v1_key.pem -encoding binary]

      decrypt $encrypted \
        $::vapidCertPath/localpriv.pem \
        $ServerPubKey \
        [ns_base64urldecode 4LLU4S9l1S9IrPTsQZkPqw] \
        [ns_base64decode WVGtEt/7tGKMNgqAeDvEPA==] \
        aesgcm
    } -result {Encryptiontest}


    cleanupTests
}
namespace delete ::Test
