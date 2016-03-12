<?php
/**
 * Created by PhpStorm.
 * @author calmacil
 *
 * This file is a part of the MfSecurity project. All rights reserved.
 */

namespace Calma\Mf\Security\User;

use Calma\Mf\Security\Data\User;

interface UserProviderInterface
{
    /**
     * @param string $username
     * @return User
     */
    public function getUser($username);
    
    /**
     * @param Calma\Mf\Security\Data\User
     * @return mixed the user unique ID
     */
    public function createUser($user);
    
    /**
     * @param Calma\Mf\Security\Data\User
     * @return bool success
     */
    public function updateUser($user);
}
