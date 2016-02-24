<?php
/**
 * @author Calmacil <thomas.lenoel@gmail.com>
 * @package \Calma\Mf\Security
 * @copyright Calmacil 2016
 * @licence MIT
 */

namespace Calma\Mf\Security\User;


class SettingsUserProvider implements UserProviderInterface
{
    private $users;

    /**
     * SettingsUserProvider constructor.
     *
     * Loads a list of users from settings_*.json
     *
     * @param $users
     */
    public function __construct($users)
    {
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
