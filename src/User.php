<?php
/**
 * @author Calmacil <thomas.lenoel@gmail.com>
 * @package \Calma\Mf\Security
 * @copyright Calmacil 2016
 * @licence MIT
 */

namespace Calma\Mf\Security;


use Calma\Mf\DataObject;

class User extends DataObject
{
    protected $_username;
    protected $_password;
    protected $_salt;
    protected $_email;
    protected $_created_at;
    protected $_updated_at;
}