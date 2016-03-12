<?php
/**
 * Created by PhpStorm.
 * @author calmacil
 *
 * This file is a part of the MfSecurity project. All rights reserved.
 */

namespace Calma\Mf\Security\Data;


use Calma\Mf\DataObject;
use Calma\Mf\PdoProvider;

class Role extends DataObject
{
    protected $_role_id;
    protected $_name;

    /**
     * Selects roles from one or several ids
     *
     * @param mixed $id
     * @param \PDO $dbh
     */
    public static function selectById($id, $dbh = null)
    {
        $dbh = $dbh ? : PdoProvider::getConnector('master');

        $sql = "SELECT `role_id`, `name` FROM `role` WHERE `role_id` ";
        $sql .= is_array($id) ? "IN (" . implode(', ', $id) . ")" : " = $id";

        $stmt = $dbh->query($sql, \PDO::FETCH_CLASS, __CLASS__);

        return $stmt->rowCount() ? $stmt->fetchAll() : false;
    }

    /**
     * Selects roles from one or several role names
     *
     * @param mixed $name
     * @param \PDO $dbh
     * @return array|bool
     */
    public static function selectByName($name, $dbh = null)
    {
        $dbh = $dbh ? : PdoProvider::getConnector('master');

        $sql = "SELECT `role_id`, `name` FROM `role` WHERE `role_name` ";
        $sql .= is_array($name) ? "IN ('" . implode("', '", $name) . "')" : " = '$name'";

        $stmt = $dbh->query($sql, \PDO::FETCH_CLASS, __CLASS__);

        return $stmt->rowCount() ? $stmt->fetchAll() : false;
    }


    public static function selectByUserId($user_id, $dbh = null)
    {

    }
}