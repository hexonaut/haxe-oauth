haxe-oauth
==========

Haxe library for OAuth 1/2 communications. Pulled from https://code.google.com/p/hxoauth/ and updated for Haxe 3.

OAuth 1 Usage
-------------

	//Get a request token
	var consumer = oauth.OAuth.connect(V1, new Consumer("CONSUMER API KEY", "CONSUMER API SECRET"));
	var requestClient = consumer.getRequestToken("https://someapi.com/oauth/request_token", "https://example.com/oauth/callback");
	
	//Redirect user to login page
	// ...
	
	//Get an access token
	var client = consumer.getAccessToken("https://someapi.com/oauth/access_token", "VERIFIER TOKEN PROVIDED BY USER");
	
	//Do API calls
	trace(client.requestJSON("https://someapi.com/users/me", true, { details:'1' }));

OAuth 2 Usage
-------------
	
	//Redirect user to login page
	// ...
	
	//Get an access token
	var consumer = oauth.OAuth.connect(V1, new Consumer("CONSUMER API KEY", "CONSUMER API SECRET"));
	var client = consumer.getAccessToken("https://someapi.com/oauth2/token", "CODE PROVIDED BY USER", "https://example.com/oauth/callback");
	
	//Do API calls
	trace(client.requestJSON("https://someapi.com/users/me", true, { details:'1' }));