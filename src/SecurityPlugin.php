<?php
/**
 * @author Calmacil <thomas.lenoel@gmail.com>
 * @package \Calma\Mf\Security
 * @copyright Calmacil 2016
 * @licence MIT
 */

namespace Calma\Mf\Security;

use Calma\Mf\Plugin\PluginInterface;
use Calma\Mf\Plugin\PluginStartInterface;
use Calma\Mf\Plugin\PluginBeforeInterface;
use Calma\Mf\Security\User\User;
use Calma\Mf\Security\User\UserProvider;

class SecurityPlugin implements PluginInterface, PluginStartInterface, PluginBeforeInterface
{
    /**
     * @var \Calma\Mf\Application
     */
    private $app;
    
    /**
     * @var mixed $options
     */
    private $options;
    
    /**
     * @var \Calma\Mf\Security\User\User
     */
    private $user;
    
    /** @var \Calma\Mf\Security\User\UserProvider
    private $user_provider;
    
    /**
     * SecurityPlugin contructor.
     * 
     * @param \Calma\Mf\Application $app
     * @param mixed $option  The Config->settings->security content
     */
    public function __construct(&$app, $options)
    {
        $this->app = $app;
        $this->options = $options;
        $this->app->coreLogger()->addNotice("Security Plugin initialized.");
    }
    
    /**
     * Retrieves logged in user if exist
     */
    public function start()
    {
        $this->user = new User;
        if (($user = $this->app['session']->get('user'))) {
            $this->user = $user;
        }
    }

    /**
     * Checks for credentials
     *
     * Controller is already instantiated
     */
    public function before()
    {
        $this->app->coreLogger()->addInfo("Checking for User session...");
        if (property_exists($this->app->getController(), 'credentials')) {
            $action = $this->app->getRequest()->getAction();

            if (array_key_exists($action, $this->app->getController()->credentials)) {

                $this->app->coreLogger()->debug('Credentials for this user: {cred}', ['cred'=>$this->user->role]);

                if (!$this->hasCredentials($this->user, $this->app->getController()->credentials[$action])) {
                    $this->app->coreLogger()->addInfo("User is not authentified, access denied.");
                    $this->app->getResponse()->display403();
                }
                $this->app->coreLogger()->addInfo("User authentified, access granted.");
            }
        }
        $this->app->coreLogger()->addInfo("Open area, go on.");
    }
    
    /**
     * Tries to authenticate the user. On success, stores the User instance in
     * the session service.
     * 
     * @param string $username
     * @param string $password
     * @return bool
     */
    public function login($username, $password)
    {
        $this->app->coreLogger()->debug("Entering SecurityPlugin::login() function for $username and $password");
        $user_provider = new UserProvider($this->options);
        if (!($user = $user_provider->getUser($username))) {
            $this->app->coreLogger()->debug("User {un} not found!", ['un'=>$username]);
            return false;
        }
        
        $hash_pwd = isset($this->options->hashmethod) ?
            hash($this->options->hashmethod, $password . $user->salt) :
            $password . $user->salt;

        $this->app->coreLogger()->debug('Given: {given}, Waited: {waited}', ['given'=>$hash_pwd, 'waited'=>$user->password]);
        
        if ($hash_pwd !== $user->password) {
            return false;
        }
        
        $this->user = $user;
        $this->user->setAuth(true);
        $this->app['session']->set('user', $this->user);
        
        return true;
    }

    public function logout()
    {
        $this->app['session']->remove('user');
    }

    /**
     * Checks if the given user has requested credentials
     * @param User $user
     * @param array|string $credentials
     * @return bool
     */
    public function hasCredentials($user, $credentials)
    {
        return $user->hasCredentials($credentials);
    }
    
    /**
     * Returns the authentication status of the current user
     * @return bool
     */
    public function isAuth()
    {
        return $this->user ? $this->user->isAuth() : false;
    }
    
    /**
     * Returns the current user.
     * @return \Calma\Mf\Security\User\User
     */
    public function getUser()
    {
        return $this->user;
    }
}
