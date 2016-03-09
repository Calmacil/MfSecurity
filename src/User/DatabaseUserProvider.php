<?php
/**
 * @author Calmacil <thomas.lenoel@gmail.com>
 * @package \Calma\Mf\Security
 * @copyright Calmacil 2016
 * @licence MIT
 */

namespace Calma\Mf\Security\User;


use Calma\Mf\Application;
use Calma\Mf\Config;
use Calma\Mf\PdoProvider;

class DatabaseUserProvider implements UserProviderInterface
{
    private $dbname;
    private $tablename;

    /**
     * @var Application;
     */
    private $app;

    public function __construct(&$app, $dbname, $tablename)
    {
        $this->dbname = $dbname;
        $this->tablename = $tablename;

        $this->app = $app;
    }

    /**
     * @param string $username
     * @return User
     */
    public function getUser($username)
    {
        try {
            $opt = [];
            if (Config::get($this->app->cfile)->debug) {
                $opt = [\PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION];
            }

            $dbh = PdoProvider::getConnector($this->dbname, $opt);

            $u = User::getByUsername($dbh, $this->tablename, $username);

            return $u;
        } catch (\PDOException $e) {
            $this->app->coreLogger()->error("PDO Error: " . $e->getMessage());
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
            $opt = [];
            if (Config::get($this->app->cfile)->debug) {
                $opt = [\PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION];
            }

            $dbh = PdoProvider::getConnector($this->dbname, $opt);
            return $user->create($dbh);
        } catch (\PDOException $e) {
            $this->app->coreLogger()->addError("PDO Error: " . $e->getMessage());
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
            $opt = [];
            if (Config::get($this->app->cfile)->debug) {
                $opt = [\PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION];
            }

            $dbh = PdoProvider::getConnector($this->dbname, $opt);
            return $user->update($dbh);
        } catch (\PDOException $e) {
            $this->app->coreLogger()->addError("PDO Error: " . $e->getMessage());
            return false;
        }
    }
}
