<?php namespace Exolnet\ServiceLayer\Auth;

use Cache;
use Exception;
use Exolnet\ServiceLayer\Auth\Exceptions\OpenIdConfigurationException;
use Exolnet\ServiceLayer\Auth\Exceptions\TokenDecodeException;
use Firebase\JWT\JWT;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Support\Collection;
use phpseclib\Crypt\RSA;

class OpenIdService
{
	/**
	 * @return string
	 */
	public function getOpenIdConfigurationUrl()
	{
		return 'https://accounts.exolnet.com/.well-known/openid-configuration';
	}

	/**
	 * @return array
	 */
	public function retrieveOpenIdConfiguration()
	{
		return $this->retrieveConfiguration($this->getOpenIdConfigurationUrl());
	}

	/**
	 * @return array
	 */
	public function getOpenIdConfiguration()
	{
		return Cache::remember('openid.configuration', 24 * 60 * 60, function() {
			return $this->retrieveOpenIdConfiguration();
		});
	}

	/**
	 * @return array
	 */
	public function retrieveJwks()
	{
		$jwksUri = array_get($this->getOpenIdConfiguration(), 'jwks_uri');
		$jwks    = $this->retrieveConfiguration($jwksUri);
		$keys    = (array)array_get($jwks, 'keys');

		return Collection::make($keys)->keyBy('kid')->toArray();
	}

	/**
	 * @return array
	 */
	public function getJwks()
	{
		return Cache::rememberForever('openid.jwks', function() {
			return $this->retrieveJwks();
		});
	}

	/**
	 * @return $this
	 */
	public function forgetJwks()
	{
		Cache::forget('openid.jwks');

		return $this;
	}

	/**
	 * @param string $kid
	 * @return array|null
	 */
	public function getPublicKey($kid)
	{
		$keys = $this->getJwks();

		if ( ! array_key_exists($kid, $keys)) {
			$this->forgetJwks();
		}

		$key = array_get($keys, $kid);

		if ( ! $key) {
			throw new OpenIdConfigurationException('Could not find JWT '. $kid .'.');
		}

		$n = base64_encode(JWT::urlsafeB64Decode($key['n']));
		$e = $key['e'];

		$rsa = new RSA();
		$rsa->loadKey('<RSAKeyValue><Modulus>'. $n .'</Modulus><Exponent>'. $e .'</Exponent></RSAKeyValue>', RSA::PUBLIC_FORMAT_XML);
		$rsa->publicExponent = $rsa->exponent;

		return $rsa->getPublicKey();
	}

	/**
	 * @return string
	 */
	public function getAuthorizedIssuer()
	{
		$configuration = $this->getOpenIdConfiguration();

		return $configuration['issuer'];
	}

	/**
	 * @param string $token
	 * @return array
	 */
	public function decode($token)
	{
		$parts = explode('.', $token);

		if (count($parts) !== 3) {
			throw new TokenDecodeException('Wrong number of segments');
		}

		$header    = json_decode(JWT::urlsafeB64Decode($parts[0]), true);
		$body      = json_decode(JWT::urlsafeB64Decode($parts[1]), true);
		$algorithm = array_get($header, 'alg');
		$iss       = array_get($body, 'iss');

		if ($algorithm !== 'RS256') {
			throw new TokenDecodeException('Invalid signature algorithm');
		}

		if ($iss !== $this->getAuthorizedIssuer()) {
			throw new TokenDecodeException('Token issuer can\'t be trust.');
		}

		$kid    = array_get($header, 'kid');
		$secret = $this->getPublicKey($kid);

		try {
			$decodedToken = JWT::decode($token, $secret, ['RS256']);
		} catch(Exception $e) {
			throw new TokenDecodeException($e->getMessage());
		}

		// validate that this JWT was made for us
		/*$audience = $decodedToken->aud;
		if (! is_array($audience)) {
			$audience = [$audience];
		}
		if (count(array_intersect($audience, $valid_audiences)) == 0) {
			throw new TokenDecodeException('This token is not intended for us.');
		}*/

		return get_object_vars($decodedToken);
	}

	/**
	 * @param string $part
	 * @return array|null
	 */
	protected function decodePart($part)
	{
		return json_decode(JWT::urlsafeB64Decode($part), true);
	}

	/**
	 * @param string $url
	 * @return array
	 */
	protected function retrieveConfiguration($url)
	{
		$response      = file_get_contents($url);
		$configuration = json_decode($response, true);

		if ( ! is_array($configuration)) {
			throw new OpenIdConfigurationException('Could not load "'. $url .'" configuration.');
		}

		return $configuration;
	}
}
