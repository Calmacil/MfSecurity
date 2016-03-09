<?php
/**
 * @author Calmacil <thomas.lenoel@gmail.com>
 * @package \Calma\Mf\Security
 * @copyright Calmacil 2016
 * @licence MIT
 */

namespace Calma\Mf\Security\User;


use Calma\Mf\Application;

class SettingsUserProvider implements UserProviderInterface
{
    private $users;

    /**
     * @var Application
     */
    private $app;

    /**
     * SettingsUserProvider constructor.
     *
     * Loads a list of users from settings_*.json
     *
     * @param $users
     */
    public function __construct(&$app, $users)
    {
        $this->app = $app;

        foreach ($users as $user) {
            $u = new User();

            $u->username = $user->username;
            $u->password = $user->password;
            if (isset($user->salt))
                $u->salt = $user->salt;
            if (isset($user->email))
                $u->email = $user->email;
            if (isset($user->role))
                $u->role = $user->role;

            $this->users[$user->username] = $u;
        }

        $this->app->getResponse()->registerFunctions('\Calma\Mf\Security\Twig\Functions');
    }

    /**
     * Returns a User instance
     *
     * @param string $username
     * @return User
     */
    public function getUser($username)
    {
        return $this->users[$username];
    }
    
    /**
     * We do not create users using this provider.
     */
    public function createUser($user)
    {
        return $user->username;
    }
    
    /**
     * We do not update users using this provider.
     */
    public function updateUser($user)
    {
        return false;
    }
}
