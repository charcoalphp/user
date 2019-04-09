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

    /** @const array ACL types. */
    const TYPES = [ 'allow', 'deny' ];

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
            $parent = Arr::get($roleStruct, 'parent');

            /** Assumes roles child roles are defined after parent roles in config. */
            if ($parent !== null && $this->acl->hasRole($parent)) {
                $parent = $this->acl->getRole($parent);
            } else {
                $roleStruct['parent'] = null;
            }

            /** Create an ACL role. */
            $this->acl->addRole($roleId, $parent);

            /** A superuser is allowed to do anything. */
            if (Arr::get($roleStruct, 'is_superuser') === true) {
                $this->acl->allow($roleId);
            } else {
                $roleStruct['is_superuser'] = false;
            }

            /** Used for building a flat, string based rule listing. */
            $rules = [];

            /** Rules are stored in an Model::objType format. */
            if (isset($roleStruct['models']) && is_array($roleStruct['models'])) {
                foreach ($roleStruct['models'] as $resource => $ruleTypes) {
                    if (!$this->acl->hasResource($resource)) {
                        $this->acl->addResource($resource);
                    }

                    $rules = array_merge($rules, $this->parseRuleTypes($ruleTypes, $roleId, $resource));
                }
            } else {
                $roleStruct['models'] = [];
            }

            /** Rules can also be stored in a user-defined format under 'privileges', allowing for flexibility. */
            if (isset($roleStruct['privileges']) && is_array($roleStruct['privileges'])) {
                $rules = array_merge($rules, $this->parseRuleTypes($roleStruct['privileges'], $roleId));
            } else {
                $roleStruct['privileges'] = [];
            }

            $roleStruct['rules'] = $rules;
        });

        $this->roles = $roles;
        $this->defaultRole = Arr::get($config, 'default_role');

        return $this;
    }

    /**
     * Parse a list of privileges sorted by rule types, add to the ACL and generate the flat rule list.
     *
     * @param  array       $ruleTypes
     * @param  string      $roleId
     * @param  string|null $resource
     * @throws RuntimeException If a rule type is not supported by the manager.
     * @return array
     */
    private function parseRuleTypes(array $ruleTypes, $roleId, $resource = null)
    {
        $rules = [];
        $strTemplate = $resource !== null ? ':type.:resource.:privilege'  : ':type.:privilege';
        $strParams   = $resource !== null ? [ ':resource'  => $resource ] : [];
        foreach ($ruleTypes as $type => $privileges) {
            if (in_array($type, self::TYPES)) {
                $strParams[':type'] = $type;
                if (is_array($privileges)) {
                    foreach ($privileges as $privilege) {
                        $strParams[':privilege'] = $privilege;
                        $this->acl->{$type}($roleId, $resource, $privilege);
                        $rules[] = strtr($strTemplate, $strParams);
                    }
                } else {
                    throw new RuntimeException(sprintf(
                        'Invalid privilege definition in ACL config for role "%s". Expected array, received %s.',
                        $roleId,
                        gettype($privileges)
                    ));
                }
            } else {
                throw new RuntimeException(sprintf(
                    'Invalid rule type "%s" in ACL config for role "%s".',
                    $type,
                    $roleId
                ));
            }
        }

        return $rules;
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

        try {
            if ($model !== null && !$this->acl->hasResource($model)) {
                $this->acl->addResource($model);
            }
            return $this->acl->isAllowed($role, $model, $privilege);
        } catch (Exception $error) {
            $this->logger->error(sprintf(
                '[ACL] Failed to assess access for role "%s", model "%s", privilege "%s". Error: %s',
                $role,
                $model,
                $privilege,
                $error->getMessage()
            ));
        }
    }
}
