package oauth;

import haxe.crypto.Md5;
import oauth.Tokens;

/**
 * OAuth 2 main entry point.
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