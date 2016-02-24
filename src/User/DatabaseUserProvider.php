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
            $query = "SELECT `username`, `password`, `salt`, `email`, `created_at`, `updated_at` FROM :tbname WHERE `username` = :username";
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
            // TODO implement
        }
    }
}
