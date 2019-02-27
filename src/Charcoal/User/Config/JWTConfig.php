<?php

namespace Charcoal\User\Config;

use InvalidArgumentException;

// From locomotivemtl/charcoal-config
use Charcoal\Config\AbstractConfig;

/**
 * JWT / auth configuration.
 */
class JWTConfig extends AbstractConfig
{
    /**
     * @var string
     */
    private $privateKey;

    /**
     * @var string
     */
    private $publicKey;

    /**
     * @var string
     */
    public $id;

    /**
     * @var string
     */
    public $issuer;

    /**
     * @var string
     */
    public $audience;

    /**
     * @var integer
     */
    public $expiration;

    /**
     * Sets the private key location.
     *
     * @param string $key The private key location.
     * @throws InvalidArgumentException If the argument is not a string.
     * @return self
     */
    public function setPrivateKey($key)
    {
        if (!is_string($key)) {
            throw new InvalidArgumentException(
                'Private key must be a string.'
            );
        }
        $this->privateKey = $key;
        return $this;
    }

    /**
     * Retrieves the private key location.
     *
     * @return string
     */
    public function privateKey()
    {
        return $this->privateKey;
    }

    /**
     * Sets the public key location.
     *
     * @param string $key The public key location.
     * @throws InvalidArgumentException If the argument is not a string.
     * @return self
     */
    public function setPublicKey($key)
    {
        if (!is_string($key)) {
            throw new InvalidArgumentException(
                'Public key must be a string.'
            );
        }
        $this->publicKey = $key;
        return $this;
    }

    /**
     * Retrieves the public key location.
     *
     * @return string
     */
    public function publicKey()
    {
        return $this->publicKey;
    }

    /**
     * Sets the private key location.
     *
     * @param string $id The private key location.
     * @throws InvalidArgumentException If the argument is not a string.
     * @return self
     */
    public function setId($id)
    {
        if (!is_string($id)) {
            throw new InvalidArgumentException(
                'Private key must be a string.'
            );
        }
        $this->id = $id;
        return $this;
    }

    /**
     * Retrieves the private key location.
     *
     * @return string
     */
    public function id()
    {
        return $this->id;
    }

    /**
     * Sets the token issuer
     *
     * @param string $issuer The private key location.
     * @throws InvalidArgumentException If the argument is not a string.
     * @return self
     */
    public function setIssuer($issuer)
    {
        if (!is_string($issuer)) {
            throw new InvalidArgumentException(
                'Private key must be a string.'
            );
        }
        $this->issuer = $issuer;
        return $this;
    }

    /**
     * Retrieves the token issuer.
     *
     * @return string
     */
    public function issuer()
    {
        return $this->issuer;
    }

    /**
     * Sets the token audience.
     *
     * @param string $audience The token audience.
     * @throws InvalidArgumentException If the argument is not a string.
     * @return self
     */
    public function setAudience($audience)
    {
        if (!is_string($audience)) {
            throw new InvalidArgumentException(
                'Private key must be a string.'
            );
        }
        $this->audience = $audience;
        return $this;
    }

    /**
     * Retrieves the token audience.
     *
     * @return string
     */
    public function audience()
    {
        return $this->audience;
    }

    /**
     * Sets the expiration (in seconds).
     *
     * @param string|integer $expiration The expiration time, in seconds.
     * @return self
     */
    public function setExpiration($expiration)
    {
        $this->expiration = (int)$expiration;
        return $this;
    }

    /**
     * Retrieves the expiration time (in seconds).
     *
     * @return integer
     */
    public function expiration()
    {
        return $this->expiration;
    }
}
