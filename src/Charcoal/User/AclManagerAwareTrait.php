<?php

namespace Charcoal\User;

// From 'charcoal-user'
use Charcoal\User\Service\AclManager;

/**
 * Provides an entity with awareness of the AclManager service.
 */
trait AclManagerAwareTrait
{
    /**
     * An AclManager service.
     *
     * @var AclManager
     */
    private $aclManager;

    /**
     * Set the AclManager service.
     *
     * @param AclManager $service
     * @return self
     */
    protected function setAclManager(AclManager $service)
    {
        $this->aclManager = $service;

        return $this;
    }

    /**
     * Retrieve the AclManager service.
     *
     * @return AclManager
     */
    protected function aclManager()
    {
        return $this->aclManager;
    }
}
