<?php

abstract class A1_Driver_Mango extends A1 {

	/**
	 * Loads the user object from database using username
	 *
	 * @param   string   username
	 * @return  object   User Object
	 */
	protected function _load_user($username)
	{
		return Mango::factory($this->_config['user_model'],array(
			$this->_config['columns']['username'] => $username
		))->load();
	}

	/**
	 * Compiles a user token based on a token and the id value of the user
	 *
	 * @param   object   User object
	 * @param   string   Token
	 * @return  string   Token String
	 */
	protected function _create_user_token($user, $token)
	{
		return $token . '.' . $user->_id;
	}
}