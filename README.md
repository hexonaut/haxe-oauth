haxe-oauth
==========

Haxe library for OAuth 1/2 communications. Pulled from https://code.google.com/p/hxoauth/ and updated for Haxe 3.

*NOTE* that I have only implemented the OAuth web flow. IE this library may not work for mobile native apps. I do not have much personal experience with native apps so if someone wants to submit a PR with this support that would be much appreciated.

OAuth 1 Usage
-------------

Assumes a JavaScript client, but it should work similarly for clients that have an integrated browser.

	//SERVER Get a request token
	var consumer = oauth.OAuth1.connect(new oauth.Consumer("CONSUMER API KEY", "CONSUMER API SECRET"));
	var requestToken = consumer.getRequestToken("https://someapi.com/oauth/request_token", "https://example.com/oauth/callback");
	
	// ... Send requestToken.token to browser (Perhaps via a JSON response) ...
	
	//CLIENT Open window to show user the authentication screen
	js.Browser.window.open(oauth.OAuth1.buildAuthUrl("https://someapi.com/oauth/authenticate", "REQUEST TOKEN PROVIDED BY SERVER"), null);
	
	//SERVER Convert the verifier token provided by the API into an access token
	var client = oauth.OAuth1.connect(new oauth.Consumer("CONSUMER API KEY", "CONSUMER API SECRET"), new oauth.Tokens.OAuth1AccessToken("ACCESS TOKEN PROVIDED BY USER"))
					.getAccessToken1("https://someapi.com/oauth/access_token", "VERIFIER TOKEN PROVIDED BY USER");
	
	//SERVER Do API calls
	
	//GET request
	trace(client.requestJSON("https://someapi.com/users/me?details=1"));
	
	//POST request
	trace(client.requestJSON("https://someapi.com/messages", true, { title:"Some Title", body:"Some Message Body" }));

OAuth 2 Usage
-------------

Assumes a JavaScript client, but it should work similarly for clients that have an integrated browser.
	
	//CLIENT Open window to show user the authentication screen
	js.Browser.window.open(oauth.OAuth2.buildAuthUrl("https://someapi.com/oauth2/auth", "CONSUMER API KEY", { redirectUri:"https://example.com/oauth/callback", scope:"LIST API ENDPOINTS YOU NEED ACCESS TO HERE", state:oauth.OAuth.OAuth2.nonce() }, [ "someAdditionalParameter" => "123" ]), null);
	
	//SERVER Convert the code provided by the API into an access token
	var consumer = oauth.OAuth2.connect(new oauth.Consumer("CONSUMER API KEY", "CONSUMER API SECRET"));
	var client = consumer.getAccessToken2("https://someapi.com/oauth2/token", "CODE PROVIDED BY USER", "https://example.com/oauth/callback");
	
	//SERVER Do API calls
	
	//GET request
	trace(client.requestJSON("https://someapi.com/users/me?details=1"));
	
	//POST request
	trace(client.requestJSON("https://someapi.com/messages", true, { title:"Some Title", body:"Some Message Body" }));
	
	//SERVER Get a new access token if the old one has expired
	client.refreshAccessToken("https://someapi.com/oauth2/token");