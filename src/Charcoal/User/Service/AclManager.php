<?php

namespace Charcoal\User\Service;

use Exception;
use InvalidArgumentException;
use RuntimeException;

// From 'illuminate/support'
use Illuminate\Support\Arr;

// From 'psr/log'
use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerAwareTrait;

// From 'zendframework/zend-permission-acl'
use Zend\Permissions\Acl\Acl;

/**
 * The Charcoal User ACL Manager.
 */
class AclManager implements LoggerAwareInterface
{
    use LoggerAwareTrait;

    /**
     * The manager's AclInterface instance.
     *
     * @var AclInterface
     */
    private $acl;

    /**
     * A store of the available ACL roles.
     *
     * @var array
     */
    private $roles = [];

    /**
     * The default role attributed to new users.
     *
     * @var string
     */
    private $defaultRole;

    /**
     * @param array $data
     */
    public function __construct(array $data)
    {
        $this->acl = new Acl();
        $this->setLogger($data['logger']);
        $this->addConfig($data['config']);
    }

    /**
     * Add a role config to the manager.
     *
     * @param array $config
     * @return self
     */
    public function addConfig($config)
    {
        $roles = $config['roles'];

        array_walk($roles, function(&$roleStruct, $roleId) {
            $parent = null;
            /** Assumes roles child roles are defined after parent roles in config. */
            if (isset($roleStruct['parent']) && $this->acl->hasRole($roleStruct['parent'])) {
                $parent = $this->acl->getRole($roleStruct['parent']);
            }

            /** Create an ACL role. */
            $this->acl->addRole($roleId, $parent);

            /** A superuser is allowed to do anything. */
            if (Arr::get($roleStruct, 'is_superuser') === true) {
                $this->acl->allow($roleId);
            } else {
                $roleStruct['is_superuser'] = false;
            }

            /** Used for building a simple string based rule listing. */
            $roleStruct['rules'] = [];

            /** Rules are stored in an Model::objType format. */
            if (isset($roleStruct['models']) && is_array($roleStruct['models'])) {
                foreach ($roleStruct['models'] as $resource => $allowedPrivileges) {
                    if (!$this->acl->hasResource($resource)) {
                        $this->acl->addResource($resource);
                    }

                    if (is_array($allowedPrivileges)) {
                        foreach ($allowedPrivileges as $allowed) {
                            $this->acl->allow($roleId, $resource, $allowed);
                            $roleStruct['rules'][] = sprintf('%s.%s', $resource, $allowed);
                        }
                    }
                }
            } else {
                $roleStruct['models'] = [];
            }

            /** Rules can also be stored in a user-defined format under 'privileges', allowing for flexibility. */
            if (isset($roleStruct['privileges']) && is_array($roleStruct['privileges'])) {
                foreach ($roleStruct['privileges'] as $allowedPrivilege) {
                    $this->acl->allow($roleId, null, $allowedPrivilege);
                    $roleStruct['rules'][] = $allowedPrivilege;
                }
            } else {
                $roleStruct['privileges'] = [];
            }
        });

        $this->roles = $roles;
        $this->defaultRole = Arr::get($config, 'default_role');

        return $this;
    }

    /**
     * Retrieve the available ACL roles.
     *
     * @return array
     */
    public function roles()
    {
        return $this->roles;
    }

    /**
     * Retrieve an available ACL role.
     *
     * @param string $ident
     * @throws InvalidArgumentException If the role cannot be found in the store.
     * @return array
     */
    public function getRole($ident)
    {
        if (!isset($this->roles[$ident])) {
            throw new InvalidArgumentException(
                'Invalid ACL role.'
            );
        }
        return $this->roles[$ident];
    }

    /**
     * Retrieve the default ACL role.
     *
     * @throws Exception If a default role is not set.
     * @return string
     */
    public function defaultRole()
    {
        if (empty($this->defaultRole)) {
            throw new Exception(
                'A default ACL role has not been set.'
            );
        }
        return $this->defaultRole;
    }

    /**
     * Determine if a given user has the capability of performing a specific action.
     *
     * @param  string $role
     * @param  string $model
     * @param  string $privilege
     * @return boolean
     */
    public function assessAccess($role = null, $model = null, $privilege = null)
    {
        if (empty($role)) {
            throw new RuntimeException('The given user does not have a role.');
        } else if (empty($model) && empty($privilege)) {
            throw new InvalidArgumentException('You must define at least one of both model and privilege.');
        }

        return $this->acl->isAllowed($role, $model, $privilege);
    }
}
