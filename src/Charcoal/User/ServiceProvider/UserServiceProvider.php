<?php

namespace Charcoal\User\ServiceProvider;

// From 'pimple/pimple'
use Pimple\Container;
use Pimple\ServiceProviderInterface;

// From 'zendframework/zend-permission-acl'
use Zend\Permissions\Acl\Acl;

// From 'charcoal-user'
use Charcoal\User\Authenticator;
use Charcoal\User\Authorizer;
use Charcoal\User\AuthToken;
use Charcoal\User\Service\AclManager;

/**
 * Charcoal User Service Provider
 *
 * ## Services
 *
 * - Authenticator
 * - Authorizer
 * - ACL Manager
 */
class UserServiceProvider implements ServiceProviderInterface
{
    /**
     * @param  Container $container A Pimple DI container.
     * @return void
     */
    public function register(Container $container)
    {
        /**
         * @param  Container $container The Pimple DI container.
         * @return AclManager
         */
        $container['acl/manager'] = function (Container $container) {
            return new AclManager([
                'config' => $container['config']['acl'],
                'logger' => $container['logger']
            ]);
        };

        if (!isset($container['authenticator'])) {
            /**
             * @param  Container $container The Pimple DI Container.
             * @return Authenticator
             */
            $container['authenticator'] = function (Container $container) {
                return new Authenticator([
                    'logger'        => $container['logger'],
                    'user_type'     => User::class,
                    'user_factory'  => $container['model/factory'],
                    'token_type'    => AuthToken::class,
                    'token_factory' => $container['model/factory']
                ]);
            };
        }

        if (!isset($container['authorizer'])) {
            /**
             * @param  Container $container The Pimple DI container.
             * @return Authorizer
             */
            $container['authorizer'] = function (Container $container) {
                return new Authorizer([
                    'logger'     => $container['logger'],
                    'aclManager' => $container['acl/manager'],
                    'resource'   => 'charcoal'
                ]);
            };
        }
    }
}
