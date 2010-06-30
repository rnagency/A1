<?php defined('SYSPATH') or die('No direct script access.');

/**
 * Sprig A1 Driver
 */
abstract class A1_Driver_Sprig extends A1 {

	/**
	 * Loads the user object from database using the token (restored from cookie)
	 *
	 * @param   array   token (token and ID)
	 * @return  object  User object
	 */
	protected function _load_user_by_token(array $token)
	{
		return Sprig::factory($this->_config['user_model'], array(
			'id' => $token[1],
			$this->_config['columns']['token'] => $token[0],
		))->load();
	}

	/**
	 * Loads the user object from database using username
	 *
	 * @param   string  username
	 * @return  object  User object
	 */
	protected function _load_user($username)
	{
		return Sprig::factory($this->_config['user_model'], array(
			$this->_config['columns']['username'] => $username
		))->load();
	}

	/**
	 * Saves the user object
	 *
	 * @param   object  User object
	 * @return  void
	 */
	protected function _save_user($user)
	{
		$user->update();
	}

}	// End of A1_Driver_Sprig

