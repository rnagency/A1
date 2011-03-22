<?php
/**
 * User AUTHENTICATION library. Handles user login and logout, as well as secure
 * password hashing.
 *
 * Uses BCrypt for hashing
 */
abstract class A1_Core {

	// Allowed salt characters
	const SALT = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

	protected $_name;
	protected $_config;
	protected $_sess;

	/**
	 * Return a static instance of A1.
	 *
	 * @return  object
	 */
	public static function instance($_name = 'a1')
	{
		static $_instances;

		if ( ! isset($_instances[$_name]))
		{
			$_config = Kohana::config($_name);
			$_driver = isset($_config['driver']) ? $_config['driver'] : 'ORM';
			$_class  = 'A1_' . ucfirst($_driver);

			$_instances[$_name] = new $_class($_name, $_config);
		}

		return $_instances[$_name];
	}

	/**
	 * Loads Session and configuration options.
	 *
	 * @return  void
	 */
	protected function __construct($_name = 'a1', $_config)
	{
		$this->_name       = $_name;
		$this->_config     = $_config;
		$this->_sess       = Session::instance( $this->_config['session']['type']);

		if ( isset($this->_config['cookie']))
		{
			if ( ! isset($this->_config['cookie']['key']))
			{
				$this->_config['cookie']['key'] = 'a1_{name}_autologin';
			}

			$this->_config['cookie']['key'] = strtr($this->_config['cookie']['key'], array('{name}' => $this->_name));
		}

		if ( ! isset($this->_config['session']['key']))
		{
			$this->_config['session']['key'] = 'a1_' . $this->_name;
		}

	}

	/**
	 * Returns TRUE is a user is currently logged in
	 *
	 * @return  boolean
	 */
	public function logged_in()
	{
		return is_object($this->get_user());
	}

	/**
	 * Returns the user - if any
	 *
	 * @return  object / FALSE
	 */
	public function get_user()
	{
		// Get the user from the session
		$user = $this->_sess->get($this->_config['session']['key']);

		// User found in session, return
		if ( is_object($user))
		{
			if ( $user->loaded())
			{
				return $user;
			}
			else
			{
				// reloading failed - user is deleted but still exists in session
				// logout (so session & cookie are cleared)
				$this->logout();
				return FALSE;
			}
		}

		if ( $this->_config['cookie']['lifetime'])
		{
			if ( ($token = Cookie::get($this->_config['cookie']['key'])))
			{
				list($hash, $username) = explode('.', $token, 2);

				if ( strlen($hash) === 32 && $username !== NULL)
				{
					// load user using username
					$user = $this->_load_user($username);

					// validates token vs hash
					if ( $user->loaded() && $this->check($hash, $user->{$this->_config['columns']['token']}))
					{
						return $this->complete_login($user,TRUE);
					}
				}
			}
		}

		return FALSE;
	}

	protected function complete_login($user, $remember = FALSE)
	{
		if ( $remember === TRUE && $this->_config['cookie']['lifetime'])
		{
			$token = text::random('alnum', 32);

			$user->{$this->_config['columns']['token']} = $this->hash($token);

			Cookie::set($this->_config['cookie']['key'], $token . '.' . $user->{$this->_config['columns']['username']}, $this->_config['lifetime']);
		}

		if ( isset($this->_config['columns']['last_login']))
		{
			$user->{$this->_config['columns']['last_login']} = time();
		}

		if ( isset($this->_config['columns']['logins']))
		{
			$user->{$this->_config['columns']['logins']}++;
		}

		$this->_save_user($user);

		// Regenerate session (prevents session fixation attacks)
		$this->_sess->regenerate();

		$this->_sess->set($this->_config['session']['key'], $user);

		return $user;
	}

	/**
	 * Attempt to log in a user.
	 *
	 * @param   string   username to log in
	 * @param   string   password to check against
	 * @param   boolean  enable auto-login
	 * @return  mixed    user if succesfull, FALSE otherwise
	 */
	public function login($username, $password, $remember = FALSE)
	{
		if ( empty($password))
		{
			return FALSE;
		}

		$user = is_object($username)
			? $username
			: $this->_load_user($username);

		return $user->loaded() && $this->check($password, $user->{$this->_config['columns']['password']})
			? $this->complete_login($user, $remember)
			: FALSE;
	}

	/**
	 * Log out a user by removing the related session variables.
	 *
	 * @param   boolean  completely destroy the session
	 * @return  boolean
	 */
	public function logout($destroy = FALSE)
	{
		if ( Cookie::get($this->_config['cookie']['key']))
		{
			Cookie::delete($this->_config['cookie']['key']);
		}

		if ($destroy === TRUE)
		{
			$this->_sess->destroy();
		}
		else
		{
			$this->_sess->delete($this->_config['session']['key']);
			$this->_sess->regenerate();
		}

		return ! $this->logged_in();
	}

	public function hash($input, $salt = NULL, $cost = NULL)
	{
		if ( ! $salt)
		{
			// Generate a random 22 character salt
			$salt = Text::random(self::SALT, 22);
		}

		if ( ! $cost)
		{
			$cost = $this->_config['cost'];
		}

		// Apply 0 padding to the cost, normalize to a range of 4-31
		$cost = sprintf('%02d', min(31, max($cost, 4)));

		// Create a salt suitable for bcrypt
		$salt = '$2a$'.$cost.'$'.$salt.'$';

		return crypt($input, $salt);
	}

	public function check($password, $hash)
	{
		// $2a$ (4) 00 (2) $ (1) <salt> (22)
		preg_match('/^\$2a\$(\d{2})\$(.{22})/D', $hash, $matches);

		// Extract the iterations and salt from the hash
		list($_, $cost, $salt) = $matches;

		return $this->hash($password, $salt, $cost) === $hash;
	}

	/**
	 * Saves the user object
	 *
	 * @param   object   User object
	 * @return  void
	 */
	protected function _save_user($user)
	{
		$user->save();
	}

	/**
	 * Loads the user object from database using username
	 *
	 * @param   string   username
	 * @return  object   User Object
	 */
	abstract protected function _load_user($username);
} // End A1