package require json

set subscription [ns_queryget subscr]
set text [ns_queryget text]
set pushstatus ""

#
# Load the Web Push API for NaviServer.
#
# For the time being, we assume, we can load the API from the same
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
    # Private key. For the time being, we use the privatePem files of
    # the demo package. Don't use this in production.
    #

    #set privPem "[ns_info home]/modules/vapid/prime256v1_key.pem"
    set privPem "$scriptDir/prime256v1_key.pem"

    #
    # Local path
    #
    set localPath $scriptDir

    #
    # send push notification
    #
    try {
	webpush::send \
	    -subscription $subscription \
	    -data $text \
	    -claim {sub mailto:georg@test.com} \
	    -privateKeyPem $privPem \
	    -localKeyPath $localPath \
	    -mode aesgcm \
	    -timeout 60

    } on error {errorMsg errorDict} {
	ns_log notice "webpush::send ended with error: $errorMsg - $errorDict"
	set errorInfo [dict get $errorDict -errorinfo]
	set jsonMessage [dict get [::json::json2dict $errorInfo] message]
	set pushstatus "$errorMsg $jsonMessage"
    } on ok {returnValue} {
	if {$returnValue < 300} {
	    set pushstatus "Push notification sent successfully!"
	} else {
	    set pushstatus "Some error occurred when sending push notification!"
	}
    }
}


ns_return 200 text/html [subst {
    <html>
    <head>
    <title>NaviServer Web Push Demo</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="https://fonts.googleapis.com/icon?family=Material+Icons">
    <link rel="stylesheet" href="https://code.getmdl.io/1.2.1/material.indigo-pink.min.css">
    <script defer src="https://code.getmdl.io/1.2.1/material.min.js"></script>
    <link rel="stylesheet" href="styles/index.css">
    </head>

    <body>
    <header>
    <h1>NaviServer Web Push Demo</h1>
    </header>

    <main>

    <p> Before being able to send messages via the push service, the
    client (web browser) has to subscribe to a service on an
    application server.  We use in this demo program
    <strong>OpenACS.org/pushnotificationsapi</strong> as application server for testing
    purposes. The public key for the service on the demo server is: <p>
    <code>BFzhXP5G5Pp5xmEfESPsd7L6N2oQZZypGd2tUR5diW9spzJFs5DXaUuM1iMVfZGunUhtHkyYjqPfcQ2bfzKzbeY</code></br>

    <p>This public key is currently hard-coded in <a
    href="https://openacs.org/pushnotificationsapi/scripts/main.js">scripts/main.js</a>,
    which is used by the subscription page.  If you have not
    subscribed to the demo service yet, please subscribe:

    <form action="https://openacs.org/pushnotificationsapi/">
    <button class="mdl-button mdl-js-button mdl-button--raised mdl-js-ripple-effect mdl-button--accent">subscribe</button>
    </form>

    <p>After subscribing to the service endpoint on the demo server,
    one can receive in this browser push messages from this service
    and one can send messages to this service.  For sending messages,
    paste the subscripion (full JSON) to the text field below.

    <form action="webpushDemo.tcl" method="post">
    <textarea name="subscr" id="subscr" rows="5" cols="120"></textarea>

    <p>You can add some text that will show up:<br>
    <textarea name="text" id="text" rows="2" cols="120"></textarea>
    <p>
    <button class="mdl-button mdl-js-button mdl-button--raised mdl-js-ripple-effect mdl-button--accent">Send Push Notification</button>
    </form>
    </p>
    <p>$pushstatus</p>
    </main>
  </body>

  </html>

  }]
