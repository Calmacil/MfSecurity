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

    /**
     * @param \PDO $dbh
     * @return bool
     */
    public function create($dbh)
    {
        $query = "INSERT INTO :tbname (`username`, `password`, `salt`, `role`, `created_at`)
                VALUES (:uname, :pwd, :salt, :role, CURRENT_TIME)";

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
    public function update($dbh)
    {
        $query = "UPDATE :tbname SET
                `password` = :pwd, `role` = :role `updated_at` = CURRENT_TIME
                WHERE `user_id` = :uid";
        $stmt = $dbh->prepare($query);

        $stmt->bindValue(':uname', $this->username);
        $stmt->bindValue(':role', $this->role);
        $stmt->bindValue(':uid', $this->user_id);

        return $stmt->execute();
    }

    /**
     * @param \PDO $dbh
     * @param string $tablename
     * @param string $username
     * @return User
     */
    public static function getByUsername($dbh, $tablename, $username)
    {
        $query = "SELECT `user_id`, `username`, `password`, `salt`, `email`, `role`, `created_at`, `updated_at`
                FROM :tbname
                WHERE `username` = :username";

        $stmt = $dbh->prepare($query);
        $stmt->setFetchMode(\PDO::FETCH_CLASS, __CLASS__);

        $stmt->bindValue(':tbname', $tablename);
        $stmt->bindValue(':username', $username);
        $stmt->execute();

        $u = $stmt->fetch();

        if ($u instanceof User)
            throw new \RuntimeException("Could not fetch User data in the right object");

        return $u;
    }
}
