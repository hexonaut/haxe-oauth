package oauth;

import haxe.crypto.Base64;
import haxe.crypto.Hmac;
import haxe.Http;
import haxe.io.Bytes;
import oauth.Tokens;

/**
 * Send a request to the API.
 * 
 * @author Sam MacPherson
 */
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
	
	public function send (?acceptType:String = null):String {
		var h = new Http(uri());
		#if js
		h.async = false;
		#end
		h.setHeader("Authorization", composeHeader());
		if (acceptType != null) {
			h.setHeader("Accept", acceptType);
		}
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