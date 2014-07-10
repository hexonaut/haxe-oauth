package oauth;

import haxe.crypto.Base64;
import haxe.crypto.Hmac;
import haxe.Http;
import haxe.io.Bytes;
import haxe.Json;
import oauth.OAuth1.Client;

using Lambda;

/**
 * OAuth 1 implementation.
 * 
 * @author Renaud Bardet
 * @author Sam MacPherson
 */

class OAuth {

	public static function connect (consumer:Consumer, ?token:Token):Client {
		return new Client(consumer, token);
	}
	
}

class Client {
	
	public var consumer(default, null):Consumer;
	public var token(default, null):Token;
	
	public function new (consumer:Consumer, ?token:Token) {
		this.consumer = consumer;
		this.token = token;
	}
	
	inline function strToMap (str:String):Map<String, String> {
		var map = new Map<String, String>();
		
		for (i in str.split('&')) {
			var pair = i.split('=');
			if (pair.length >= 2) map.set(StringTools.urlDecode(pair[0]), StringTools.urlDecode(pair[1]));
		}
		
		return map;
	}
	
	public function getRequestToken (uri:String, callback:String, ?post:Bool = true):Client {
		var req = new Request(uri, consumer, token, post, null, { oauth_callback:callback } );
		req.sign();
		var result = strToMap(req.send());
		
		if (!result.exists("oauth_token")) throw "Failed to get request token.";
		
		return new Client(consumer, new Token(result.get("oauth_token"), result.get("oauth_token_secret")));
	}
	
	public function getAccessToken (uri:String, verifier:String, ?post:Bool = true):Client {
		var result = requestUrlEncoded(uri, post, { oauth_verifier:verifier });
		
		if (!result.exists("oauth_token")) throw "Failed to get access token.";
		
		return new Client(consumer, new Token(result.get("oauth_token"), result.get("oauth_token_secret")));
	}
	
	public function requestUrlEncoded (uri:String, ?post:Bool = false, ?postData:Dynamic):Map<String, String> {
		return strToMap(request(uri, post, postData));
	}
	
	public function requestJSON (uri:String, ?post:Bool = false, ?postData:Dynamic):Dynamic {
		return Json.parse(request(uri, post, postData));
	}
	
	public function request (uri:String, ?post:Bool = false, ?postData:Dynamic):String {
		var req = new Request(uri, consumer, token, post, postData);
		req.sign();
		return req.send();
	}
	
}

class Request {
	
	var consumer:Consumer;
	var token:Token;
	
	var scheme:String;
	var authority:String;
	var path:String;
	var query:String;
	var fragment:String;
	var post:Bool;
	
	var credentials:Map<String, String>;
	
	var data:Dynamic;
	
	public function new (uri:String, consumer:Consumer, token:Token, ?post:Bool = false, ?data:Dynamic, ?extraOAuthParams:Dynamic) {
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
		if (token != null) credentials.set("oauth_token", token.key);
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
		var key = encode(consumer.secret) + '&' + ((token != null && token.secret != null) ? encode(token.secret) : '');
		var hash = new Hmac(SHA1);
		var bytes = hash.make(Bytes.ofString(key), Bytes.ofString(text));
		var digest = Base64.encode(bytes);
		credentials.set("oauth_signature", digest);
	}
	
	public function send ():String {
		var h = new Http(uri());
		h.setHeader("Authorization", composeHeader());
		if (data != null) h.setPostData(postDataStr());
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
		
		buf.add("OAuth ") ;
		
		var params = credentials.keys();
		for (p in params) {
			buf.add(encode(p));
			buf.add("=\"") ;
			buf.add(encode(credentials.get(p)));
			buf.add('"') ;
			if (params.hasNext())
				buf.add(', ');
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

class Token {
	
	public var key(default, null):String;
	public var secret(default, null):String;
	
	public function new (key, ?secret) {
		this.key = key;
		this.secret = secret;
	}
	
}