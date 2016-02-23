<?php
/**
 * @author Calmacil <thomas.lenoel@gmail.com>
 * @package \Calma\Mf\Security
 * @copyright Calmacil 2016
 * @licence MIT
 */

namespace Calma\Mf\Security;


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
            if (isset($user->email))
                $u->email = $user->email;

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
}