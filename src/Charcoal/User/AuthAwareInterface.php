<?php

namespace Charcoal\User;

/**
 * Defines a class with authentication and authorization capabilities.
 *
 * Implementation, as trait, provided by {@see \Charcoal\User\AuthAwareTrait}.
 */
interface AuthAwareInterface
{
    /**
     * @return booleans
     */
    public function isAuthorized();

    /**
     * @param array|null $permissions The list of required permissions to check.
     * @return boolean
     */
    public function hasPermissions($permissions);
}
