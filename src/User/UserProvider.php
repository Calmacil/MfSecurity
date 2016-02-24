<?php
/**
 * @author Calmacil <thomas.lenoel@gmail.com>
 * @package \Calma\Mf\Security
 * @copyright Calmacil 2016
 * @licence MIT
 */

namespace Calma\Mf\Security\User;

/**
 * Class UserProvider
 * @package Calma\Mf\Security
 *
 * Need params:
 * - settings
 *   - security
 *     - provider which can be either 'settings' or 'database' currently
 *     - hashmethod /!\ NOT REQUIRED HERE, implement it in the SecurityPlugin for example
 *     - dbname for the 'database' provider, matches with a db.json entry
 *     - tablename as well
 */
class UserProvider implements UserProviderInterface
{
    private $provider = 'settings';
    private $hashmethod;
    private $dbname;
    private $tablename;


    /**
     * @var UserProviderInterface
     */
    private $provider_real;

    /**
     * UserProvider constructor.
     *
     * You have to pass Config::get('settings')->security to this constructor.
     *
     * @param $options
     */
    public function __construct($options)
    {
        if (isset($options->provider))
            $this->provider = $options->provider;
        if (isset($options->hashmethod))
            $this->hashmethod = $options->hashmethod;
        if (isset($options->dbname))
            $this->dbname = $options->dbname;
        if (isset($options->tablename))
            $this->tablename = $options->tablename;

        if ($this->provider == 'settings') {
            if (!isset($options->users))
                throw new \RuntimeException("The specified users source is not provided.");
            $this->provider_real = new SettingsUserProvider($options->users);
        } elseif ($this->provider == 'database') {
            if (!$this->dbname || !$this->tablename)
                throw new \RuntimeException("The specified users source is not provided.");
            $this->provider_real = new DatabaseUserProvider($this->dbname, $this->tablename);
        }
    }

    public function getUser($username)
    {
        return $this->provider_real->getUser($username);
    }
}
