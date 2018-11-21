<?php

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                        Initialise Joomla Dependencies                                             //
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//Initialise Joomla Helpers
define('_JEXEC', 1);

if (file_exists(__DIR__ . '/defines.php'))
{
include_once __DIR__ . '/defines.php';
}

if (!defined('_JDEFINES'))
{
define('JPATH_BASE',  '/var/www/html');
require_once JPATH_BASE . '/includes/defines.php';
}

require_once JPATH_BASE . '/includes/framework.php';

// Instantiate the application.
$app = JFactory::getApplication('site');


$error_message = "";

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                     LDAP CONNECITON AND AUTHENTICATION                                            //
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

set_time_limit(30);
error_reporting(E_ALL);
ini_set('error_reporting', E_ALL);
ini_set('display_errors',1);

$progress_tracker = "Initialising login system - ";

// retrieve username and password from user submitted form
$username = $_POST['uname']; 
$pswd = $_POST['psw'];

// config & Proxy User
$ldapserver = '0.0.0.0';	// Add AD Server IP address here
$ldapuser   = 'Proxy_User'; // Add details of AD proxy user account here
$ldappass   = 'PASSWORD';   // Add PASSWORD for AD proxy user account here
$ldaptree   = "OU=organizational_unit,DC=Domain_Component"; // Define the Proxy User Tree
$ldaptreesearch = "OU=organizational_unit,DC=Domain_Component"; // Define the Tree in which you wish to search for Users

// connect 
$ldapconn = ldap_connect($ldapserver) or die("Could not connect to LDAP server.");

if($ldapconn) {
    // binding to ldap server and search for entered user details using proxy log-in
    $ldapbind = ldap_bind($ldapconn, $ldapuser, $ldappass) or die ("Error trying to bind: ".ldap_error($ldapconn));
    // verify binding
    if ($ldapbind) {
        $progress_tracker .= "Attempting LDAP bind using proxy user : Success! -";

        $attributes = array("displayname", "mail", "samaccountname"); // Get the required attributes for the user to pass to Joomla
		
        $result = ldap_search($ldapconn,$ldaptreesearch, "(sAMAccountName=".$username.")", $attributes) or die ("Error in search query: ".ldap_error($ldapconn));
        $data = ldap_get_entries($ldapconn, $result);
		
        // iterate over array and prepare data for user
        for ($i=0; $i<$data["count"]; $i++) {
 				  if (strtolower($data[$i]["samaccountname"][0]) == strtolower($username)) {
				  $dn = $data[$i]['dn'];
			    }
        }

		
		if (isset($dn) && !empty($dn)) {
			 
			//--------------------- Bind using entered user details to LDAP directory ----------------------------------- 
			$my_binding = @ldap_bind($ldapconn,$dn,$pswd); 
			 
			if(!$my_binding){ 
				$progress_tracker .=  "Attempting user authentication via LDAP : Error - Invalid Password - "; 
				$error_message = "Invalid Password - Please ensure you are using your correct Active Directory password";
			} 
			else{ 
				$progress_tracker .= "Attempting user authentication via LDAP : Success! - "; 
				$ldap_success = 1;
			}
		} else {
			$progress_tracker .= "Attempting user authentication via LDAP : Error - user not found! - ";
			$error_message = "No User found - please ensure you are using your correct Active Directory username";
		}
		
    } else {
        $progress_tracker .=  "LDAP bind failed...";
        $error_message = "Unable to connect to service - Please try again later";
    }

}

// all done? clean up
ldap_close($ldapconn);

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                             Attempt Log-in to Joomla with Returned LDAP Credentials                               //
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// If LDAP Bind sucessful - Authenticate against joomla
if (!empty($ldap_success)) {
	
//Create Credentials Array
$credentials = array();
$credentials['username'] = $username;
$credentials['password'] = $_POST['psw'];
$login = "0";
$match = false;

// Get a database object
$db    = JFactory::getDbo();
$query = $db->getQuery(true)
->select('id, password, username')
->from('###_users') // Enter The User Table Details for Joomla
->where('username=' . $db->quote($credentials['username']));

$db->setQuery($query);
$result = $db->loadObject();

if ($result) {$match = JUserHelper::verifyPassword($credentials['password'], $result->password, $result->id);}

if ($match === true)
	{
	// If matching then Log In
	$user = JUser::getInstance($result->id);
	$result = $app->login($credentials);
	$user = JFactory::getUser();
	$progress_tracker .=  'Attempting Joomla Authentication : Success!';
	$login = "1";
	}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                            If LDAP Credentials fail but matching Username found                                   //
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

if ($login === "0" and isset($result->username))
	{
	$progress_tracker .= 'Attempting Joomla Authentication : Failed! - ';

	if(strtolower($credentials['username']) == strtolower($result->username))
	{
		$progress_tracker .= "Username Found In Joomla Database - ";

		// User exists so we update joomla password to match AD profile
		$username = $_POST['uname']; 
		$pswd = $_POST['psw'];
		
		// Use Joomla Hash function to create hashed password
		$hashedpsw = JUserHelper::hashPassword($pswd);
		
		// Get Database connection
		$db = JFactory::getDbo();
		$query = $db->getQuery(true);
			
		$query->update($db->quoteName('###_users'))->set($db->quoteName('password') . ' = '.$db->quote($hashedpsw))->where($db->quoteName('username') . ' = '.$db->quote($username));
		   
		$db->setQuery($query); 
		$result = $db->execute();
			
		$progress_tracker .= "Password mis-match between AD and Joomla : Sync in Progress - ";
			
		// Then Re-attempt login with new password
		
		//Create Credentials Array
		$credentials = array();
		$credentials['username'] = $username;
		$credentials['password'] = $_POST['psw'];
		
		// Get a database object
		$db    = JFactory::getDbo();
		$query = $db->getQuery(true)
		->select('id, password')
		->from('###_users') // Enter The User Table Details for Joomla
		->where('username=' . $db->quote($credentials['username']));
		
		$db->setQuery($query);
		$result = $db->loadObject();
		
		$match = JUserHelper::verifyPassword($credentials['password'], $result->password, $result->id);
		
			if ($match === true)
			{
			    // If matching then Log In
			    $user = JUser::getInstance($result->id);
				  $result = $app->login($credentials);
				  $user = JFactory::getUser();
			    $progress_tracker .= 'Attempting Joomla Authentication with updated password : Success!';
				$login = "1";
			} else {$progress_tracker .= 'Attempting Joomla Authentication with updated password : Failed!';}	
		} else { $progress_tracker .= "No Matching Username found in Joomla Database - "; }
	} 


///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                          If LDAP Credentials fail & No Username found in Joomla                                  //
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// No User Found in Joomla to match LDAP - Create new user and login
if ($login === "0") {
 
	$progress_tracker .= "Attempting Joomla Authentication : Failed! - No user found with this name in Joomla DB - Adding New User - ";
	
	//Create variables for array
	$username = $_POST['uname']; 
	$pswd = $_POST['psw'];
	$displayname = $data[0]["displayname"][0];
	$useremail = $data[0]["mail"][0];

	// Import Joomla User Helper Classes
	jimport('joomla.user.helper');

	// Create new user array			
	$newuserdata = array(
	  "name"=>$displayname,
	  "username"=>$username,
	  "password"=>$pswd,
	  "email"=>$useremail,
	  "block"=>0,
	  "groups"=>array("1","2")
	);
	
	// create new user with JUser function	
	$newuser = new JUser;

	// Bind new user array with the User Object
	try {
	$newuser->bind($newuserdata);
	}
	catch(Exception $e){
		throw new Exception($e->getMessage(), 500, $e);
	}

	// Save the new user array data to database
	try {
		$newuser->save();
	}
	catch(Exception $e){
		throw new Exception($e->getMessage(), 500, $e);
	}	           


	// re-attempt login with user credentials
	
	//Create Credentials Array
	$credentials = array();
	$credentials['username'] = $username;
	$credentials['password'] = $_POST['psw'];
	$match = false;
		
	// Get a database object
	$db    = JFactory::getDbo();
	$query = $db->getQuery(true)
	->select('id, password')
	->from('###_users') // Enter The User Table Details for Joomla
	->where('username=' . $db->quote($credentials['username']));
		
	$db->setQuery($query);
	$result = $db->loadObject();
		
	$match = JUserHelper::verifyPassword($credentials['password'], $result->password, $result->id);
		
		if ($match === true)
			{
			    // If matching then Log In
			    $user = JUser::getInstance($result->id);
				  $result = $app->login($credentials);
				  $user = JFactory::getUser();
			    $progress_tracker .= 'Attempting Joomla Authentication with new user profile : Success!';
				$login= "1";
					
			} else { $progress_tracker .= "Attempting Joomla Authentication with new user profile : Failed";}

}


///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                              If User fails to Authenticate against LDAP server                                    //
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

} else { $progress_tracker .= "No Joomla Authentication Attempted - Username or password not found in LDAP"; $login = "0";}




///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                         LOG ERRORS TO LOG FILE - TBC                                              //
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////




///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                             AJAX / JSON Response                                                  //
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


$response = array($login, $progress_tracker, $error_message);

header('Content-type: application/json');
echo json_encode($response);


?>
