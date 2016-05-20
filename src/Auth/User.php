<?php namespace Exolnet\ServiceLayer\Auth;

use Illuminate\Contracts\Auth\Authenticatable;

class User implements Authenticatable
{
	/**
	 * @var array
	 */
	protected $data;

	/**
	 * User constructor.
	 *
	 * @param array $data
	 */
	public function __construct(array $data)
	{
		$this->data = $data;
	}

	/**
	 * @return string
	 */
	public function getIss()
	{
		return $this->data['iss'];
	}

	/**
	 * @return string
	 */
	public function getSub()
	{
		return $this->data['sub'];
	}

	/**
	 * @return string
	 */
	public function getEmail()
	{
		return $this->data['email'];
	}

	/**
	 * Get the unique identifier for the user.
	 *
	 * @return mixed
	 */
	public function getAuthIdentifier()
	{
		return $this->getSub();
	}

	/**
	 * Get the password for the user.
	 *
	 * @return string
	 */
	public function getAuthPassword()
	{
		return null;
	}

	/**
	 * Get the token value for the "remember me" session.
	 *
	 * @return string
	 */
	public function getRememberToken()
	{
		return null;
	}

	/**
	 * Set the token value for the "remember me" session.
	 *
	 * @param  string $value
	 * @return void
	 */
	public function setRememberToken($value)
	{
		return null;
	}

	/**
	 * Get the column name for the "remember me" token.
	 *
	 * @return string
	 */
	public function getRememberTokenName()
	{
		return null;
	}
}
