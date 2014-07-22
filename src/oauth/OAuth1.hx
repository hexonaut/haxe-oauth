package oauth;

import oauth.Tokens;

/**
 * OAuth 1 main entry point.
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