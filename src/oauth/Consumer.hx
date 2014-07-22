package oauth;

/**
 * The primary authentication information. Usually this is static and provided when you register with the API.
 * 
 * @author Sam MacPherson
 */
class Consumer {
	
	public var key(default, null):String;
	public var secret(default, null):String;
	
	public function new (key:String, secret:String) {
		this.key = key;
		this.secret = secret;
	}
	
}