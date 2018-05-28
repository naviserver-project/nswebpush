package require tcltest

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
    } -result {11111}
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
      set validEndpoint {endpoint https://updates.push.services.mozilla.com/wpush/v2/gAAAAABa8D5exlSZQM0iWk_5614sP0qFMbY85kGpJejPz2HBaGdJse9CbVn6kK5UbjHTWq-nE3KtTUu24boaSRV2IqSfABxstDuhMltofoCPjF2t9hq3j6gMWFR07MLIB4YGOEz0UHCCWVsFOeSNCfXU0iKo66CDn515SdNsw3N9UvQNAWUHvQ0 auth 4LLU4S9l1S9IrPTsQZkPqw p256dh BNvOAPaPCCfpNCMR4AccTffxD8YMQbfIBWieLxgZE1qgU-YVVT5mOD7CaRRqg5ykA7_f8jm2VuOPZLvHn0moHas}
      set validClaim {sub mailto:georg@test.com}
      set validPem $::vapidCertPath/prime256v1_key.pem
      if {[webpush $validEndpoint "" $validClaim $validPem] < 300} {
        set result 1
      }
      if {[webpush $validEndpoint "testdata" $validClaim $validPem] < 300} {
        append result 1
      }
    } -result {11}

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
        $salt]
      set key [lindex $keynonce 0]
      set nonce [lindex $keynonce 1]
      set result [ns_base64encode $key]
      concat $result [ns_base64encode $nonce]
    } -result {bwUz6s4vfAi5a9xGFBVRXg== n14o2v4+edg7+ggO}

    test encrypt {} -body {
      ns_base64encode [encrypt "Push notification payload!" \
        $::vapidCertPath/prime256v1_key.pem \
        [ns_base64urldecode 4LLU4S9l1S9IrPTsQZkPqw] \
        [ns_base64urldecode BNvOAPaPCCfpNCMR4AccTffxD8YMQbfIBWieLxgZE1qgU-YVVT5mOD7CaRRqg5ykA7_f8jm2VuOPZLvHn0moHas] \
        [ns_base64decode WVGtEt/7tGKMNgqAeDvEPA==]]
    } -result {w4gGftd6LQZeveV3ub/i3IfkUq9e3yShR1GGGDhOAo1OujxgrJaCQvr+}

    cleanupTests
}
namespace delete ::Test
