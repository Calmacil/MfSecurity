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
    protected $_username;
    protected $_password;
    protected $_salt;
    protected $_email;
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
}
