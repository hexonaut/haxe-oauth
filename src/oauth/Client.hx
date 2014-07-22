package oauth;

import haxe.Json;
import oauth.Tokens;

/**
 * Make calls to an API on behalf of a user.
 * 
 * @author Sam MacPherson
 */
class Client {
	
	public var version(default, null):OAuthVersion;
	public var consumer(default, null):Consumer;
	public var accessToken:Null<AccessToken>;
	public var refreshToken:Null<RefreshToken>;
	
	public function new (version:OAuthVersion, consumer:Consumer) {
		this.version = version;
		this.consumer = consumer;
	}
	
	inline function strToMap (str:String):Map<String, String> {
		var map = new Map<String, String>();
		
		for (i in str.split('&')) {
			var pair = i.split('=');
			if (pair.length >= 2) map.set(StringTools.urlDecode(pair[0]), StringTools.urlDecode(pair[1]));
		}
		
		return map;
	}
	
	public function getRequestToken (uri:String, callback:String, ?post:Bool = true):RequestToken {
		if (!version.match(V1)) throw "Request token only applies to OAuth 1.";
		
		var req = new Request(version, uri, consumer, null, post, null, { oauth_callback:callback } );
		req.sign();
		var result = strToMap(req.send());
		
		if (!result.exists("oauth_token")) throw "Failed to get request token.";
		
		return new RequestToken(result.get("oauth_token"), result.get("oauth_token_secret"));
	}
	
	public function getAccessToken1 (uri:String, verifier:String, ?post:Bool = true):Client {
		if (!version.match(V1)) throw "Cannot call an OAuth 1 method from a non-OAuth 1 flow.";
		
		var result = requestUrlEncoded(uri, post, { oauth_verifier:verifier });
		
		if (!result.exists("oauth_token") || !result.exists("oauth_token_secret")) throw "Failed to get access token.";
		
		accessToken = new OAuth1AccessToken(result.get("oauth_token"), result.get("oauth_token_secret"));
		return this;
	}
	
	public function getAccessToken2 (uri:String, code:String, redirectUri:String, ?post:Bool = true):Client {
		if (!version.match(V2)) throw "Cannot call an OAuth 2 method from a non-OAuth 2 flow.";
		
		var result = jsonToMap(requestJSON(uri, post, { code:code, client_id:consumer.key, client_secret:consumer.secret, redirect_uri:redirectUri, grant_type:"authorization_code" }));
		
		if (!result.exists("access_token")) throw "Failed to get access token.";
		
		var c = new Client(version, consumer);
		c.accessToken = new OAuth2AccessToken(result.get("access_token"), Std.parseInt(result.get("expires_in")));
		if (result.exists("refresh_token")) c.refreshToken = new RefreshToken(result.get("refresh_token"));
		return c;
	}
	
	public function refreshAccessToken (uri:String, ?post:Bool = true):Client {
		if (!version.match(V2)) throw "Cannot call an OAuth 2 method from a non-OAuth 2 flow.";
		if (refreshToken == null) throw "Missing refresh token.";
		
		var result = jsonToMap(requestJSON(uri, post, { refresh_token:refreshToken.token, client_id:consumer.key, client_secret:consumer.secret, grant_type:"refresh_token" }));
		
		if (!result.exists("access_token")) throw "Failed to get access token.";
		
		accessToken = new OAuth2AccessToken(result.get("access_token"), Std.parseInt(result.get("expires_in")));
		return this;
	}
	
	public inline function requestUrlEncoded (uri:String, ?post:Bool = false, ?postData:Dynamic):Map<String, String> {
		return strToMap(request(uri, post, postData));
	}
	
	public inline function requestJSON (uri:String, ?post:Bool = false, ?postData:Dynamic):Dynamic {
		return Json.parse(request(uri, post, postData));
	}
	
	inline function jsonToMap (json:Dynamic):Map<String, String> {
		var map = new Map<String, String>();
		
		for (i in Reflect.fields(json)) {
			map.set(i, Reflect.field(json, i));
		}
		
		return map;
	}
	
	public function request (uri:String, ?post:Bool = false, ?postData:Dynamic):String {
		var req = new Request(version, uri, consumer, accessToken, post, postData);
		if (version == V1) req.sign();
		return req.send();
	}
	
}