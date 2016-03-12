<?php
/**
 * @author Calmacil <thomas.lenoel@gmail.com>
 * @package \Calma\Mf\Security
 * @copyright Calmacil 2016
 * @licence MIT
 */

namespace Calma\Mf\Security\Data;


use Calma\Mf\DataObject;
use Calma\Mf\PdoProvider;

class User extends DataObject
{

    protected $relations = [
        "Roles" => "loadRolesByUserId"
    ];

    /* DB fields */
    protected $_user_id;
    protected $_username;
    protected $_password;
    protected $_salt;
    protected $_email;
    protected $_created_at;
    protected $_updated_at;

    protected $__Roles;
    
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
        if (is_array($this->__roles)) {
            foreach ($this->__roles as $role) {
                if ($credentials == $role->name) return true;
            }
        }

        return false;
    }

    /**
     * @param \PDO $dbh
     * @return bool
     */
    public function create($tablename = 'users', $dbh=null)
    {
        $dbh = $dbh ? : PdoProvider::getConnector('master');

        $query = "INSERT INTO `$tablename` (`username`, `password`, `salt`, `created_at`)
                VALUES (:uname, :pwd, :salt, CURRENT_TIME)";

        $stmt = $dbh->prepare($query);

        $stmt->bindValue(':uname', $this->username);
        $stmt->bindValue(':pwd', $this->password);
        $stmt->bindValue(':salt', $this->salt);
        $stmt->bindValue(':role', $this->role);

        if (!$stmt->execute()) {
            return false;
        }

        return $dbh->lastInsertId();
    }

    /**
     * @param \PDO $dbh
     * @return mixed
     */
    public function update($tablename = 'users', $dbh = null)
    {
        $dbh = $dbh ? : PdoProvider::getConnector('master');

        $query = "UPDATE `$tablename` SET
                `password` = :pwd, `updated_at` = CURRENT_TIME
                WHERE `user_id` = :uid";
        $stmt = $dbh->prepare($query);

        $stmt->bindValue(':uname', $this->username);
        $stmt->bindValue(':uid', $this->user_id);

        return $stmt->execute();
    }

    /**
     * @param \PDO $dbh
     * @param string $tablename
     * @param string $username
     * @return User
     */
    public static function getByUsername($username, $tablename='users', $dbh = null)
    {
        $dbh = $dbh ? : PdoProvider::getConnector('master');

        $query = "SELECT `user_id`, `username`, `password`, `salt`, `email`, `created_at`, `updated_at`
                FROM `$tablename`
                WHERE `username` = :username";

        $stmt = $dbh->prepare($query);
        $stmt->setFetchMode(\PDO::FETCH_CLASS, '\Calma\Mf\Security\Data\User');

        $stmt->bindValue(':username', $username);
        if (!$stmt->execute()) return false;

        $u = $stmt->fetch() or die(\PDO::error_get_last());

        if (!($u instanceof User)) {
            $c = get_class($u);
            throw new \RuntimeException("Could not fetch User data in the right object: $c");
        }

        return $u;
    }

    protected function loadRolesByUserId()
    {
        $sql = "SELECT `role_id`, `name` FROM `role` WHERE `role_id` IN
            (SELECT `role_id` FROM `users_roles` WHERE `user_id` = :uid";

        $dbh = PdoProvider::getConnector('master');
        $stmt = $dbh->prepare($sql);
        $stmt->bindValue(':uid', $this->_user_id);
        $stmt->setFetchMode(\PDO::FETCH_CLASS, Role);

        $stmt->execute();

        return $stmt->rowCount() ? $stmt->fetchAll() : false;
    }
}
