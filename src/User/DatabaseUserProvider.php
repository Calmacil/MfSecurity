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
            return User::getByUsername($dbh, $this->tablename, $username);
        } catch (\PDOException $e) {
            return false;
        }
    }
    
    /**
     * Creates a new user in the database and returns it's user_id
     * @param \Calma\Mf\Security\User\User the user
     * @return mixed The identifier
     */
    public function createUser($user)
    {
        try {
            $dbh = PdoProvider::getConnector($this->dbname);
            return $user->create($dbh);
        } catch (\PDOException $e) {
            return false;
        }
    }
    
    /**
     * Updates the user. Only password and role can be updated.
     * 
     * @param \Calma\Mf\Security\User\User $user The user
     * @return bool $success
     */
    public function updateUser($user)
    {
        try {
            $dbh = PdoProvider::getConnector($this->dbname);
            return $user->update($dbh);
        } catch (\PDOException $e) {
            return false;
        }
    }
}
