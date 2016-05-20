<?php namespace Exolnet\ServiceLayer\Auth\Middleware;

use Closure;
use Exolnet\ServiceLayer\Auth\Exceptions\TokenDecodeException;
use Exolnet\ServiceLayer\Auth\OpenIdService;
use Exolnet\ServiceLayer\Auth\User;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Http\Request;
use Symfony\Component\HttpKernel\Exception\HttpException;

class AuthenticateOpenId
{
	/**
	 * The Guard implementation.
	 *
	 * @var \Illuminate\Contracts\Auth\Guard
	 */
	protected $auth;

	/**
	 * @var \Exolnet\ServiceLayer\Auth\OpenIdService
	 */
	protected $openIdService;

	/**
	 * Create a new filter instance.
	 *
	 * @param  \Illuminate\Contracts\Auth\Guard $auth
	 * @param \Exolnet\ServiceLayer\Auth\OpenIdService $openIdService
	 */
	public function __construct(Guard $auth, OpenIdService $openIdService)
	{
		$this->auth = $auth;
		$this->openIdService = $openIdService;
	}

	/**
	 * Handle an incoming request.
	 *
	 * @param  \Illuminate\Http\Request  $request
	 * @param  \Closure  $next
	 * @return mixed
	 */
	public function handle(Request $request, Closure $next)
	{
		try {
			$token = $this->extractToken($request);

			if ( ! $token) {
				throw new HttpException(401, 'Unauthorized');
			}

			$jwt = $this->openIdService->decode($token);

			if ( ! $jwt) {
				throw new HttpException(401, 'Unauthorized');
			}

			$this->auth->login(new User($jwt));

			return $next($request);
		} catch (TokenDecodeException $e) {
			throw new HttpException(401, 'Unauthorized');
		}
	}

	/**
	 * @param \Illuminate\Http\Request $request
	 * @return string|null
	 */
	protected function extractToken(Request $request)
	{
		$authorization = $request->header('Authorization');

		if ($authorization && preg_match('/^Bearer\s(\S+)$/i', $authorization, $match)) {
			return $match[1];
		}

		return $request->get('access_token') ?: null;
	}
}
