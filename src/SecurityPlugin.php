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
use Calma\Mf\Security\User\UserProvider;

class SecurityPlugin implements PluginInterface, PluginStartInterface
{
    /**
     * @var Calma\Mf\Application
     */
    private $app;
    
    /**
     * @var mixed $options
     */
    private $options;
    
    /**
     * @var Calma\Mf\Security\User\User
     */
    private $user;
    
    /** @var Calma\Mf\Security\User\UserProvider
    private $user_provider;
    
    /**
     * SecurityPlugin contructor.
     * 
     * @param Calma\Mf\Application $app
     * @param mixed $option  The Config->settings->security content
     */
    public function __construct(&$app, $options)
    {
        $this->app = $app;
        $this->options = $options;
    }
    
    /**
     * Retrives logged in user if exist
     */
    public function start()
    {
        if (($user = $this->app['session']->get('user'))) {
            $this->user = $user;
        }
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
        $user_provider = new UserProvider($this->options);
        if (!($user = $user_provider->getUser($username))) {
            return false;
        }
        
        $hash_pwd = isset($this->options->hashmethod) ?
            hash($this->options->hashmethod, $password . $user->salt) :
            $password . $user->salt;
        
        if ($hash_pwd !== $user->password) {
            return false;
        }
        
        $this->user = $user;
        $this->user->setAuth(true);
        $this->app['session']->set('user', $this->user);
        
        return true;
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
