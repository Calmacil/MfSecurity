<?php
/**
 * Created by PhpStorm.
 * @author calmacil
 *
 * This file is a part of the MfSecurity project. All rights reserved.
 */

namespace Calma\Mf\Security\User;


interface UserProviderInterface
{
    /**
     * @param string $username
     * @return User
     */
    public function getUser($username);
}
