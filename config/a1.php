<?php

return array(

	'driver'     => 'ORM', // orm/jelly/mango/sprig
	'user_model' => 'user',
	'cost'       => 12,    // Bcrypt Cost - any number between 4 and 31 -> higher = stronger hash

	'cookie'     => array(
		'key'         => 'a1_{name}_autologin',
		'lifetime'    => 1209600, // two weeks
	),

	'columns'   => array(
		'username'    => 'username',
		'password'    => 'password',
		'token'       => 'token',
		//'last_login'=> 'last_login', // (optional)
		//'logins'    => 'logins'      // (optional)
	),

	'session'  => array(
		'type'        => 'native' // native or database
	),

	'prevent_browser_cache' => TRUE // Enable this to have A1 set the cache-control & pragma headers when a user is logged in (prevents user from using back button after logout)
);
