<?php defined('SYSPATH') or die('No direct access allowed.');

/**
 * Example:
 *   APPATH/classes/model/user.php:
 *   class Model_User extends Model_A1_User_Jelly {
 *
 *       public static function initialize(Jelly_Meta $meta)
 *       {
 *           $meta->table('user')
 *               ->fields(array(
 *                   'logins' => new Field_Integer,
 *                   //'token' => new Field_String(),
 *               ));
 *
 *           parent::initialize($meta);
 *       }
 *   }
 *
 *   ------------------------------
 *
 *   APPATH/classes/controller/user.php:
 *   class Controller_Frontend_User extends Controller_Frontend_Template {
 *
 *   public function action_signup()
 *   {
 *       // ...
 *
 *       try
 *       {
 *           $user = Jelly::factory('user', array(
 *               'username' => 'user',
 *               'password' => 'bI$hkEk*2bj',
 *               'password' => 'bI$hkEk*2bj',
 *           ))->save();
 *       }
 *       catch(Validate_Exception $e)
 *       {
 *          // catch validate errors
 *       }
 * 
 *       // ...
 *   }
 *   
 */
abstract class Model_A1_User_Jelly extends Jelly_Model {

	/**
	 * @param Jelly_Meta $meta
	 */
	public static function initialize(Jelly_Meta $meta)
	{
		$meta->fields(array(
			'id' => new Field_Primary,
			'username' => new Field_String(array(
				'unique' => TRUE,
					'rules' => array(
						'not_empty' => NULL,
						'min_length' => array(4),
						'max_length' => array(50),
					)
				)),
			'password' => new Field_Password(array(
				'hash_with' => array('Model_A1_User_Jelly', 'hash_password'),
				'rules' => array(
					'not_empty' => NULL,
					'min_length' => array(6),
					'max_length' => array(50),
				)
			)),
			'password_confirm' => new Field_Password(array(
				'in_db' => FALSE,
				'callbacks' => array(
					'matches' => array('Model_A1_User_Jelly', 'password_matches')
				),
				'rules' => array(
					'not_empty' => NULL,
					'min_length' => array(6),
					'max_length' => array(50),
				)
			)),
		));
	}

	/**
	 * Validate callback wrapper for checking password match
	 * @param Validate $array
	 * @param string $field
	 * @return void
	 */
	public static function password_matches(Validate $array, $field)
	{
		if ($array['password'] !== $array[$field])
		{
			$array->error($field, 'matches', array('param1' => 'password'));
		}
	}

	/**
	 * Hash callback using the A1 library
	 *
	 * @param string password to hash
	 * @return string
	 */
	public static function hash_password($password)
	{
		return A1::instance()->hash_password($password);
	}
}