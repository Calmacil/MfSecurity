<?php
/**
 * @author Calmacil <thomas.lenoel@gmail.com>
 * @package \Calma\Mf\Security\Twig
 * @copyright Calmacil 2016
 * @licence MIT
 */

namespace Calma\Mf\Security\Twig;


class Functions
{
    public static function has_credentials(\Twig_Environment $env, $credentials)
    {
        $glob = $env->getGlobals();
        $user = $glob['_APP_']['security']->getUser();

        return $glob['_APP_']['security']->hasCredentials($user, $credentials);
    }
}