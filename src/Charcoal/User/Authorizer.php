<?php

namespace Charcoal\User;

use InvalidArgumentException;

// From 'psr/log'
use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerAwareTrait;

// From 'zendframework/zend-permissions-acl'
use Zend\Permissions\Acl\Acl;

// From 'charcoal-user'
use Charcoal\User\AclManagerAwareTrait;
use Charcoal\User\UserInterface;

/**
 * The authorizer service helps with user authorization (permission checking).
 *
 * ## Constructor dependencies
 *
 * Constructor dependencies are passed as an array of `key=>value` pair.
 * The required dependencies are:
 *
 * - `aclManager` A Zend ACL (Access-Control-List) instance.
 * - `logger`     A PSR3 logger instance.
 * - `resource`   The ACL resource identifier (string).
 *
 * ## Checking permissions
 *
 * To check if the ACL Manager allows a list of permissions (aka privileges):
 *
 * - `userAllowed(UserInterface $user, string[] $aclPermissions)`
 * - `rolesAllowed(string[] $roles, string[] $aclPermissions)`
 */
class Authorizer implements LoggerAwareInterface
{
    use AclManagerAwareTrait;
    use LoggerAwareTrait;

    /**
     * The ACL resource identifier.
     *
     * @var string $resource
     */
    private $resource;

    /**
     * @param array $data Class dependencies.
     */
    public function __construct(array $data)
    {
        $this->setLogger($data['logger']);
        $this->setAclManager($data['aclManager']);
        $this->setResource($data['resource']);
    }

    /**
     * @param string[] $aclRoles       The ACL roles to validate against.
     * @param string[] $aclPermissions The acl permissions to validate.
     * @return boolean Wether the permissions are allowed for a given list of roles.
     */
    public function rolesAllowed($aclRoles, array $aclPermissions)
    {
        if (is_string($aclRoles)) {
            $aclRoles = [ $aclRoles ];
        }

        foreach ($aclRoles as $aclRole) {
            foreach ($aclPermissions as $aclPermission) {
                if (is_array($aclPermission)) {
                    $aclModel = $aclPermission['model'];
                    $aclPrivilege = $aclPermission['privilege'];
                } else {
                    $aclModel = null;
                    $aclPrivilege = $aclPermission;
                }

                if (!$this->aclManager()->assessAccess($aclRole, $aclModel, $aclPrivilege)) {
                    $this->logger->error(sprintf(
                        'Role "%s" is not allowed permission "%s"',
                        $aclRole,
                        $aclPrivilege
                    ));
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * Determine if a user can perform a certain action.
     *
     * @param UserInterface $user           The user to validate against.
     * @param string[]      $aclPermissions The ACL permissions to validate.
     * @return boolean
     */
    public function userAllowed(UserInterface $user, array $aclPermissions)
    {
        return $this->rolesAllowed($user->roles(), $aclPermissions);
    }

    /**
     * @param string $resource The ACL resource identifier.
     * @throws InvalidArgumentException If the resource identifier is not a string.
     * @return void
     */
    private function setResource($resource)
    {
        if (!is_string($resource)) {
            throw new InvalidArgumentException(
                'ACL resource identifier must be a string.'
            );
        }
        $this->resource = $resource;
    }

    /**
     * @return string
     */
    protected function resource()
    {
        return $this->resource;
    }
}
