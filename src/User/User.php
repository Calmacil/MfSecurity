<?php
/**
 * @author Calmacil <thomas.lenoel@gmail.com>
 * @package \Calma\Mf\Security
 * @copyright Calmacil 2016
 * @licence MIT
 */

namespace Calma\Mf\Security\User;


use Calma\Mf\DataObject;

class User extends DataObject
{
    /* DB fields */
    protected $_user_id;
    protected $_username;
    protected $_password;
    protected $_salt;
    protected $_email;
    protected $_role;
    protected $_created_at;
    protected $_updated_at;
    
    /**
     * @var bool
     */
    private $auth = false;
    
    /**
     * Indicates if the user is authentified
     * @return bool
     */
    public function isAuth()
    {
        return $this->auth;
    }
    
    /**
     * @param bool $auth Sets the user identified (or not)
     */
    public function setAuth($auth)
    {
        $this->auth = $auth;
    }

    /**
     * @param array|string $credentials     A single role or an array of roles, returns true if at least one matches
     * @return bool
     */
    public function hasCredentials($credentials)
    {
        if (is_string($credentials)) {
            return ($this->_role === $credentials);
        }

        if (is_array($credentials)) {
            return in_array($this->_role, $credentials);
        }

        return false;
    }
}
