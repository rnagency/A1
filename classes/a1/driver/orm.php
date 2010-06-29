<?php

abstract class A1_Driver_ORM extends A1 {

	/**
	 * Loads the user object from database using the token (restored from cookie)
	 *
	 * @param   array   token (token and ID)
	 * @return  object  User Object
	 */
	protected function _load_user_by_token(array $token)
	{
		return ORM::factory($this->_config['user_model'])
			->where($this->_config['columns']['token'],'=',$token[0])
			->find($token[1]);
	}

	/**
	 * Loads the user object from database using username
	 *
	 * @param   string   username
	 * @return  object   User Object
	 */
	protected function _load_user($username)
	{
		return ORM::factory($this->_config['user_model'], array( $this->_config['columns']['username'] => $username));
	}
}