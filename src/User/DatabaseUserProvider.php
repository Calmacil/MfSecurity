<?php
/**
 * @author Calmacil <thomas.lenoel@gmail.com>
 * @package \Calma\Mf\Security
 * @copyright Calmacil 2016
 * @licence MIT
 */

namespace Calma\Mf\Security\User;


use Calma\Mf\PdoProvider;

class DatabaseUserProvider implements UserProviderInterface
{
    private $dbname;
    private $tablename;

    public function __construct($dbname, $tablename)
    {
        $this->dbname = $dbname;
        $this->tablename = $tablename;
    }

    /**
     * @param string $username
     * @return User
     */
    public function getUser($username)
    {
        try {
            $dbh = PdoProvider::getConnector($this->dbname);
            $query = "SELECT `user_id`, `username`, `password`, `salt`, `email`, `role`, `created_at`, `updated_at`
                FROM :tbname
                WHERE `username` = :username";

            $stmt = $dbh->prepare($query);
            $stmt->setFetchMode(PDO::FETCH_CLASS, '\\Calma\\Mf\\Security\\User');

            $stmt->bindValue(':tbname', $this->tablename);
            $stmt->bindValue(':username', $username);
            $stmt->execute();

            $u = $stmt->fetch();

            if (!is_a($u, '\\Calma\\Mf\\Security\\User'))
                throw new \RuntimeException("Could not fetch User data in the right object");

            return $u;
        } catch (\PDOException $e) {
            return false;
        }
    }
    
    /**
     * Creates a new user in the database and returns it's user_id
     * @param Calma\Mf\Security\User\User the user
     * @return mixed The identifier
     */
    public function createUser($user)
    {
        try {
            $dbh = PdoProvider::getConnector($this->dbname);
            $query = "INSERT INTO :tbname (`username`, `password`, `salt`, `role`, `created_at`)
                VALUES (:uname, :pwd, :salt, :role, CURRENT_TIME)";
            
            $stmt = $dbh->prepare($query);
            
            $stmt->bindValue(':uname', $user->username);
            $stmt->bindValue(':pwd', $user->password);
            $stmt->bindValue(':salt', $user->salt);
            $stmt->bindValue(':role', $user->role);
            
            if (!$stmt->execute()) {
                return false;
            }
            
            return $dbh->lastInsertId();
        } catch (\PDOException $e) {
            return false;
        }
    }
    
    /**
     * Updates the user. Only password and role can be updated.
     * 
     * @param Calma\Mf\Security\User\User $user The user
     * @return bool $success
     */
    public function updateUser($user)
    {
        try {
            $dbh = PdoProvider::getConnector($this->dbname);
            $query = "UPDATE :tbname SET
                `password` = :pwd, `role` = :role `updated_at` = CURRENT_TIME
                WHERE `user_id` = :uid";
            $stmt = $dbh->prepare($query);
            
            $stmt->bindValue(':uname', $user->username);
            $stmt->bindValue(':role', $user->role);
            $stmt->bindValue(':uid', $user->user_id);
            
            return $stmt->execute();
        } catch (\PDOException $e) {
            return false;
        }
    }
}
