<?php

namespace Charcoal\User\Acl;

use InvalidArgumentException;

// From Pimple
use Pimple\Container;

// From 'charcoal-translator'
use Charcoal\Translator\TranslatorAwareTrait;

// From 'charcoal-core'
use Charcoal\Model\AbstractModel;

/**
 * ACL Roles define hierarchical allowed and denied permissions.
 *
 * They can be attached to user accounts for fine-grained permission control.
 */
class Role extends AbstractModel
{
    use TranslatorAwareTrait;

    const SEPARATOR = ',';

    /**
     * @var string|null $ident
     */
    public $ident;

    /**
     * The parent ACL role.
     *
     * This role will inherit all of its parent's permissions.
     *
     * @var string $parent
     */
    public $parent;

    /**
     * The user-friendly name.
     *
     * @var \Charcoal\Translator\Translation
     */
    public $name;

    /**
     * List of explicitely allowed permissions.
     *
     * @var string[]|null $allowed
     */
    public $allowed;

    /**
     * List of explicitely denied permissions.
     *
     * @var string[]|null $denied
     */
    public $denied;

    /**
     * @var boolean
     */
    private $superuser = false;

    /**
     * @var integer
     */
    private $position;

    /**
     * ACL Role can be used as a string (ident).
     *
     * @return string
     */
    public function __toString()
    {
        if ($this->ident === null) {
            return '';
        }
        return $this->ident;
    }

    /**
     * @return string
     */
    public function key()
    {
        return 'ident';
    }

    /**
     * @param string|Role $parent Role's parent.
     * @return self
     */
    public function setParent($parent)
    {
        $this->parent = (string)$parent;
        return $this;
    }

    /**
     * @return string
     */
    public function getParent()
    {
        return $this->parent;
    }

    /**
     * @param string[]|string|null $allowed The allowed permissions for this role.
     * @throws InvalidArgumentException If the passed arguments is not an array, null, or a comma-separated string.
     * @return self
     */
    public function setAllowed($allowed)
    {
        if ($allowed === null) {
            $this->allowed = null;
            return $this;
        }

        if (is_string($allowed)) {
            $allowed = explode(self::SEPARATOR, $allowed);
            $allowed = array_map('trim', $allowed);
        }
        if (!is_array($allowed)) {
            throw new InvalidArgumentException(
                'Invalid allowed value. Must be an array, null, or a comma-separated string.'
            );
        }
        $this->allowed = $allowed;
        return $this;
    }

    /**
     * @return string[]|null
     */
    public function getAllowed()
    {
        return $this->allowed;
    }

    /**
     * @param string[]|string|null $denied The denied permissions for this role.
     * @throws InvalidArgumentException If the passed arguments is not an array, null, or a comma-separated string.
     * @return self
     */
    public function setDenied($denied)
    {
        if ($denied === null) {
            $this->denied = null;
            return $this;
        }

        if (is_string($denied)) {
            $denied = explode(self::SEPARATOR, $denied);
            $denied = array_map('trim', $denied);
        }
        if (!is_array($denied)) {
            throw new InvalidArgumentException(
                'Invalid denied value. Must be an array, null, or a comma-separated string.'
            );
        }
        $this->denied = $denied;
        return $this;
    }

    /**
     * @return string[]|null
     */
    public function getDenied()
    {
        return $this->denied;
    }

    /**
     * @param boolean $isSuper The superuser flag.
     * @return self
     */
    public function setSuperuser($isSuper)
    {
        $this->superuser = !!$isSuper;
        return $this;
    }

    /**
     * @return boolean
     */
    public function getSuperuser()
    {
        return $this->superuser;
    }

    /**
     * @param integer|string|null $position The role's ordering position.
     * @return self
     */
    public function setPosition($position)
    {
        $this->position = (int)$position;
        return $this;
    }

    /**
     * @return integer
     */
    public function getPosition()
    {
        return $this->position;
    }

    /**
     * @param Container $container Pimple DI container.
     * @return void
     */
    protected function setDependencies(Container $container)
    {
        parent::setDependencies($container);

        $this->setTranslator($container['translator']);
    }
}
