package require json

set subscription [ns_queryget subscr]
set text [ns_queryget text]
set pushstatus ""

#
# Load the Web Push API for NaviServer.
#
# For the timne being, we assume, we can load the API from the same
# directory, from which this script is run. In general, it should be
# loaded in advance via e.g. a module. This should be supported soon.
#
set script [ns_url2file [ns_conn url]]
set scriptDir [file dirname $script]
source $scriptDir/webpush.tcl
ns_log notice "script $scriptDir/webpush.tcl was loaded"

if {$subscription ne ""} {
    #
    # Subscription will be in JSON
    #
    set subscrDict [::json::json2dict $subscription]
    set keys [dict get $subscrDict keys]

    #
    # transform to correctly formatted tcl dict
    #
    set subscription [subst {endpoint [dict get $subscrDict endpoint] auth [dict get $keys auth] p256dh [dict get $keys p256dh]}]

    #
    # private key is here
    #
    set privPem "[ns_info home]/modules/vapid/prime256v1_key.pem"

    #
    # Local path
    #
    set localPath $scriptDir

    #
    # send push notification
    #
    if {[webpush::send \
	     -subscription $subscription \
	     -data $text \
	     -claim {sub mailto:georg@test.com} \
	     -privateKeyPem $privPem \
	     -localKeyPath $localPath \
	     -mode aesgcm \
	     -timeout 60] < 300} {
	set pushstatus "Push notification sent successfully!"
    } else {
	set pushstatus "Some error occurred when sending push notification!"
    }
}


ns_return 200 text/html [subst {
  <html>
  <head>
  <title>Push Demo</title>
  </head>
  <body>
  <h1>A Webpush Demo</h1>
  <p>
  <form action="webpushDemo.tcl" method="post">
  Enter a subscription to this public key: BFzhXP5G5Pp5xmEfESPsd7L6N2oQZZypGd2tUR5diW9spzJFs5DXaUuM1iMVfZGunUhtHkyYjqPfcQ2bfzKzbeY<br>
  (you can subscribe <a href=https://openacs.org/pushnotificationsapi/>here</a>)<br>
  <input type="text" name="subscr" id="subscr"><br>
  You can add some text that will show up:<br>
  <input type="text" name="text" id="text"><br>
  <input type="submit" value="Send Push Notification">
  </form>
  </p>
  <p>$pushstatus</p>
  </body>

  </html>

  }]
