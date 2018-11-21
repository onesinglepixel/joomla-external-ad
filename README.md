# joomla-external-ad
Script for allowing Joomla authentication against an external LDAP server

Process

1. User submits a html form with Username and Password
2. PHP script uses a PROXY USER to connect to remote server
3. PROXY USER is used to perform a LDAP search for supplied Username
4. Should Username exist attempt USER log into LDAP Server
5. If sucessful it then uses these details to attempt Joomla Log in
6. If sucessful : Redirect user to homepage
7. If failed but username does exist in joomla update password in joomla to match
8. If sucessful : Redirect user to homepage
9. If failed because no username that matches exists create a new user to match LDAP user
10. If sucessful : Redirect user to homepage
11. If failed submit error log to terminal and return errors to form for user to address
