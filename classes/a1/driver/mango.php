<?php

abstract class A1_Driver_Mango extends A1 {

	/**
	 * Loads the user object from database using the token (restored from cookie)
	 *
	 * @param   array   token (token and ID)
	 * @return  object  User Object
	 */
	protected function _load_user_by_token(array $token)
	{
		return Mango::factory($this->_config['user_model'],array(
			'_id'                              => $token[1],
			$this->_config['columns']['token'] => $token[0]
		))->load();
	}

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

	/**
	 * Saves the user object
	 *
	 * @param   object   User object
	 * @return  void
	 */
	protected function _save_user($user)
	{
		$user->update();
	}

}