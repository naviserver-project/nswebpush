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
    ns_log notice "Using $privPem as .pem file containing the private key of the server"

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
	set errorInfo     [dict get $errorDict -errorinfo]
	set jsonErrorDict [::json::json2dict $errorInfo]
	if {[dict exists $jsonErrorDict message]} {
	    set pushstatus "$errorMsg [info get $jsonErrorDict message]"
	} else {
	    set pushstatus "$errorMsg $errorInfo"
	}
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
    <link rel="stylesheet" href="index.css">
    <style>
    .js-subscription-json {color: grey;}
    </style>
    </head>

    <body>
    <header>
    <h1>NaviServer Web Push Demo</h1>
    </header>

    <main>
    <div class="mdl-grid">
    <div class="mdl-cell mdl-cell--12-col">
     <p>Before being able to send messages via this push service, the
    client (web browser) has to subscribe to a service on an
    application server.  We use in this demo
    <strong>OpenACS.org</strong> as an application server for testing
    purposes.

    <p>This service depends on The Google/Mozilla Web Push services
    amd was tested with recent versions of Firefox and Chrome on
    Windows, Linux, macOS and Android (currently just Chrome).  It
    does not work with Safari or on any browser in iOS due to limited
    support on these Browsers.

    </div>
    <div class="mdl-cell mdl-cell--6-col">
    <p>The application server is identified over its public key, which
    is for this demo hard-coded in <a href="webpush.js">webpush.js</a>
    included by this demo.  If you have not subscribed to the demo
    service yet, please subscribe:
    <p>
      <button disabled class="js-push-btn mdl-button mdl-js-button mdl-button--raised mdl-js-ripple-effect">
        Subscribe
      </button>
    </p>

    </div>
    <div class="mdl-cell mdl-cell--6-col">
    <img src="webpush-subscribe.png" width="320">
    </div>
    </div>

    <section class="subscription-details js-subscription-details is-invisible">

    <div class="mdl-grid">
    <div class="mdl-cell mdl-cell--12-col">
    <p>Once you've subscribed your user, your subscription is
    typically sent to the server and saved there in a database such
    that the server can send you a message via this subscription.
    The subscription is not saved for this demo. 
    </div>
    <div class="mdl-cell mdl-cell--6-col">
    <p>The application server can now send an encrypted message to the
    Push Service, which will deliver the push message to the
    client. The TTL option specifies, how long the Push Server will
    try to deliver it.
    </div>
    <div class="mdl-cell mdl-cell--6-col">
    <img src="webpush-send.png" width="320">
    </div>

    <div class="mdl-cell mdl-cell--12-col">
    <form action="webpush-demo.tcl" method="post">
    <strong>Your subscription:</strong><br>
    <textarea class="js-subscription-json" name="subscr" id="subscr" rows="5" cols="120" readonly></textarea>
    <p>
    <p>
    You can send now yourself a message using this notification.<br>
    <strong>Text to be sent to your subscription via Web Push:</strong><br>
    <textarea name="text" id="text" rows="2" cols="120"></textarea>
    <p>
    <button class="mdl-button mdl-js-button mdl-button--raised mdl-js-ripple-effect mdl-button--accent">Send Push Notification</button>
    </form>

    <p>$pushstatus</p>
    </div>
    </div>
    <p>For the technical details behind this demo,
    see <a href="report.html">Implementing Web Push with NaviServer</a>.
    </section>

    </main>

  <script src="webpush.js"></script>

  <script src="https://code.getmdl.io/1.2.1/material.min.js"></script>

  </html>

  }]
