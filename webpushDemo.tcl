package require json

set subscription	[ns_queryget subscr]
set text [ns_queryget text]
set pushstatus ""

if {$subscription ne ""} {
  # load webpush
  source [ns_info home]/pages/pushnotificationsapi/webpush.tcl
  # subscription will be in json
  set subscrDict [::json::json2dict $subscription]
  set keys [dict get $subscrDict keys]
  # transform to correctly formated tcl dict
  set subscription [subst {endpoint [dict get $subscrDict endpoint] auth [dict get $keys auth] p256dh [dict get $keys p256dh]}]
  # private key is here
  set privPem "[ns_info home]/modules/vapid/prime256v1_key.pem"
  # local path
  set localPath "[ns_info home]/pages/pushnotificationsapi"
  # send push notification
  if {[webpush $subscription $text {sub mailto:georg@test.com} $privPem $localPath aesgcm 60] < 300} {
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
