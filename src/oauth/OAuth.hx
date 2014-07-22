package oauth;

import haxe.crypto.Base64;
import haxe.crypto.Hmac;
import haxe.crypto.Md5;
import haxe.Http;
import haxe.io.Bytes;
import haxe.Json;

using Lambda;

enum OAuthVersion {
	V1;
	V2;
}

class RequestToken {
	
	public var token(default, null):String;
	public var secret(default, null):String;
	
	public function new (token:String, secret:String) {
		this.token = token;
		this.secret = secret;
	}
	
}

class AccessToken {
	
	public var token(default, null):String;
	
	public function new (token:String) {
		this.token = token;
	}
	
}

class OAuth1AccessToken extends AccessToken {
	
	public var secret(default, null):String;
	
	public function new (token:String, ?secret:String) {
		super(token);
		
		this.secret = secret;
	}
	
}

class OAuth2AccessToken extends AccessToken {
	
	public var expires(default, null):Int;
	
	public function new (token:String, ?expires:Int) {
		super(token);
		
		this.expires = expires;
	}
	
}

class RefreshToken {
	
	public var token(default, null):String;
	
	public function new (token:String) {
		this.token = token;
	}
	
}

/**
 * OAuth 1.
 * 
 * @author Renaud Bardet
 * @author Sam MacPherson
 */

class OAuth1 {
	
	public static function connect (consumer:Consumer, ?accessToken:OAuth1AccessToken):Client {
		var c = new Client(V1, consumer);
		c.accessToken = accessToken;
		return c;
	}

	public static inline function buildAuthUrl (baseUri:String, requestToken:String):String {
		return '$baseUri?oauth_token=$requestToken';
	}
	
}

/**
 * OAuth 2.
 * 
 * @author Renaud Bardet
 * @author Sam MacPherson
 */

class OAuth2 {

	public static function connect (consumer:Consumer, ?accessToken:OAuth2AccessToken, ?refreshToken:RefreshToken):Client {
		var c = new Client(V2, consumer);
		c.accessToken = accessToken;
		c.refreshToken = refreshToken;
		return c;
	}
	
	public static inline function nonce ():String {
		return Md5.encode(Std.string(Math.random()));
	}
	
	public static inline function buildAuthUrl (baseUri:String, clientId:String, ?opts:{ ?redirectUri:String, ?scope:String, ?state:String }, ?additionalParams:Map<String, String>):String {
		var uri = '$baseUri?response_type=code&client_id=${StringTools.urlEncode(clientId)}';
		
		if (opts != null) {
			if (opts.redirectUri != null) uri += '&redirect_uri=${StringTools.urlEncode(opts.redirectUri)}';
			if (opts.scope != null) uri += '&scope=${StringTools.urlEncode(opts.scope)}';
			if (opts.state != null) uri += '&state=${StringTools.urlEncode(opts.state)}';
		}
		
		if (additionalParams != null) {
			for (i in additionalParams.keys()) {
				uri += '&$i=${StringTools.urlEncode(additionalParams.get(i))}';
			}
		}
		
		return uri;
	}
	
}

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

class Request {
	
	var version:OAuthVersion;
	var consumer:Consumer;
	var token:AccessToken;
	
	var scheme:String;
	var authority:String;
	var path:String;
	var query:String;
	var fragment:String;
	var post:Bool;
	
	var credentials:Map<String, String>;
	
	var data:Dynamic;
	
	public function new (version:OAuthVersion, uri:String, consumer:Consumer, token:AccessToken, ?post:Bool = false, ?data:Dynamic, ?extraOAuthParams:Dynamic) {
		this.version = version;
		this.consumer = consumer;
		this.token = token;
		
		// see http://tools.ietf.org/html/rfc3986#page-50
		var uriReg = ~/^(([^:\/?#]+):)?(\/\/([^\/?#]*))?([^?#]*)(\?([^#]*))?(#(.*))?/;
		
		if (!uriReg.match(uri)) throw "Malformed URI" ;
		
		scheme = uriReg.matched(2);
		authority = uriReg.matched(4);
		path = uriReg.matched(5);
		query = uriReg.matched(7);
		fragment = uriReg.matched(9);
		
		this.post = post;
		
		this.data = data;
		
		credentials = new Map<String, String>();
		credentials.set("oauth_consumer_key", consumer.key);
		if (token != null) credentials.set("oauth_token", token.token);
		credentials.set("oauth_signature_method", "HMAC-SHA1");
		credentials.set("oauth_timestamp", Std.string(Std.int(Date.now().getTime()/1000)));
		credentials.set("oauth_nonce", generateNonce());
		credentials.set("oauth_version", "1.0");
		if (extraOAuthParams != null) {
			for (i in Reflect.fields(extraOAuthParams)) {
				credentials.set(i, Reflect.field(extraOAuthParams, i));
			}
		}
	}
	
	public function sign ():Void {
		var text = baseString();
		var key = encode(consumer.secret) + '&' + 
			if (token != null) {
				var oauth1Token = cast(token, OAuth1AccessToken);
				oauth1Token.secret != null ? encode(cast(token, OAuth1AccessToken).secret) : '';
			} else '';
		var hash = new Hmac(SHA1);
		var bytes = hash.make(Bytes.ofString(key), Bytes.ofString(text));
		var digest = Base64.encode(bytes);
		credentials.set("oauth_signature", digest);
	}
	
	public function send ():String {
		var h = new Http(uri());
		#if js
		h.async = false;
		#end
		h.setHeader("Authorization", composeHeader());
		if (data != null) {
			h.setHeader("Content-Type", "application/x-www-form-urlencoded");
			h.setPostData(postDataStr());
		}
		var ret = '';
		h.onData = function(d) ret = d;
		h.request(post);
		return ret;
	}
	
	function uri ():String {
		var buf = new StringBuf();
		
		buf.add(scheme);
		buf.add("://");
		buf.add(authority);
		buf.add(path);
		if (query != null && query != '') {
			buf.add('?');
			buf.add(query);
		}
		if (fragment != null && fragment != '') {
			buf.add('#');
			buf.add(fragment);
		}
		
		return buf.toString();
		
	}
	
	function composeHeader ():String {
		var buf = new StringBuf() ;
		
		switch (version) {
			case V1:
				buf.add("OAuth ");
				
				var params = credentials.keys();
				for (p in params) {
					buf.add(encode(p));
					buf.add("=\"") ;
					buf.add(encode(credentials.get(p)));
					buf.add('"') ;
					if (params.hasNext())
						buf.add(', ');
				}
			case V2:
				if (token != null) buf.add("Bearer " + token.token);
		}
		
		return buf.toString();
	}
	
	function baseString ():String {
		var buf = new StringBuf();
		
		buf.add(post ? "POST" : "GET");
		buf.add('&');
		buf.add(encode(baseStringURI()));
		buf.add('&') ;
		buf.add(encode(baseStringParameters()));
		
		return buf.toString();
		
	}
	
	function baseStringURI ():String {
		var buf = new StringBuf() ;
		
		buf.add(scheme.toLowerCase()) ;
		buf.add("://") ;
		var portReg = ~/^([^:]*):([0-9]*)/;
		var host = if (portReg.match(authority))
				portReg.matched(1);
			else
				authority;
		buf.add(host.toLowerCase());
		buf.add(path);
		
		return buf.toString();
	}
	
	function baseStringParameters() : String {
		// do not use a Hash as identically named parameters MUST appear twice
		var params = new Array<{ k:String, v:String }>();
		
		function separateKV (s) {
			var kv = s.split('=');
			if (kv[1] == null) kv[1] = '';
			return { k:encode(kv[0]), v:encode(kv[1]) };
		}
		
		if (query != null) {
			for (pair in query.split('&').map(separateKV))
				params.push(pair);
		}
		
		if (data != null) {
			for (f in Reflect.fields(data))
				params.push({ k:encode(f), v:encode(Reflect.field(data, f)) });
		}
		
		for (k in credentials.keys()) {
			params.push( { k:encode( k ), v : encode(credentials.get(k)) } );
		}
		
		params.sort(
			function( _x1 : { k : String, v : String }, _x2 : { k : String, v : String } )
			{
				
				return if ( _x1.k < _x2.k )
						-1 ;
					else if ( _x1.k > _x2.k )
						1 ;
					else if ( _x1.v < _x2.v )
						-1 ;
					else
						1 ;
				
			} ) ;
		
		function joinKV (p: { k:String, v:String } ) return p.k + '=' + p.v;
		
		return params.map(joinKV).join('&');
	}
	
	function postDataStr ():String {
		var buf = new StringBuf();
		
		var first = true;
		for (i in Reflect.fields(data)) {
			if (!first) buf.add('&');
			buf.add(encode(i) + "=" + encode(Reflect.field(data, i)));
			first = false;
		}
		
		return buf.toString();
	}
	
	static inline function generateNonce () {
		var chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
		var nonce = '';
		for (i in 0 ... 6)
			nonce += chars.substr(Std.int(Math.random() * chars.length), 1);
		
		return nonce;
	}
	
	static inline function encode (s:String) {
		return StringTools.urlEncode(s);
	}
	
}

class Consumer {
	
	public var key(default, null):String;
	public var secret(default, null):String;
	
	public function new (key:String, secret:String) {
		this.key = key;
		this.secret = secret;
	}
	
}