<?php
/**
 * Created by PhpStorm.
 * @author calmacil
 *
 * This file is a part of the MfSecurity project. All rights reserved.
 */

namespace Calma\Mf\Security\Twig;


class SecurityExtension extends \Twig_Extension
{
    /**
     * @return string
     */
    public function getName()
    {
        return "mf_security_ext";
    }

    /**
     * @return array|\Twig_SimpleFunction[]
     */
    public function getFunctions()
    {
        return [
            new \Twig_SimpleFunction('has_credentials', [$this, 'hasCredentials'], ['needs_environment' => true])
        ];
    }

    /**
     * @param \Twig_Environment $env
     * @param $credentials
     * @return mixed
     */
    public function hasCredentials(\Twig_Environment $env, $credentials)
    {
        $glob = $env->getGlobals();
        $user = $glob['_APP_']['security']->getUser();

        return $glob['_APP_']['security']->hasCredentials($user, $credentials);
    }
}