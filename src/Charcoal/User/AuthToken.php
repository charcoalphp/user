<?php

namespace Charcoal\User;

use DateTime;
use DateTimeInterface;
use InvalidArgumentException;

// From 'charcoal-core'
use Charcoal\Model\AbstractModel;

// From 'charcoal-user'
use Charcoal\User\AuthTokenMetadata;

/**
 * Authorization token; to keep a user logged in
 */
class AuthToken extends AbstractModel
{
    /**
     * @var string
     */
    private $ident;

    /**
     * @var string
     */
    private $token;

    /**
     * The user ID should be unique and mandatory.
     *
     * @var string
     */
    private $userId;

    /**
     * @var DateTimeInterface|null
     */
    private $expiry;

    /**
     * Token creation date (set automatically on save)
     * @var DateTimeInterface|null
     */
    private $created;

    /**
     * Token last modified date (set automatically on save and update)
     * @var DateTimeInterface|null
     */
    private $lastModified;

    /**
     * @return string
     */
    public function key()
    {
        return 'ident';
    }

    /**
     * @param string $ident The token ident.
     * @return self
     */
    public function setIdent($ident)
    {
        $this->ident = $ident;
        return $this;
    }

    /**
     * @return string
     */
    public function getIdent()
    {
        return $this->ident;
    }

    /**
     * @param string $token The token.
     * @return self
     */
    public function setToken($token)
    {
        $this->token = $token;
        return $this;
    }

    /**
     * @return string
     */
    public function getToken()
    {
        return $this->token;
    }


    /**
     * @param string $id The user ID.
     * @throws InvalidArgumentException If the user ID is not a string.
     * @return self
     */
    public function setUserId($id)
    {
        if (!is_string($id)) {
            throw new InvalidArgumentException(
                'Set User ID: identifier must be a string'
            );
        }
        $this->userId = $id;
        return $this;
    }

    /**
     * @return string
     */
    public function getUserId()
    {
        return $this->userId;
    }

    /**
     * @param DateTimeInterface|string|null $expiry The date/time at object's creation.
     * @throws InvalidArgumentException If the date/time is invalid.
     * @return self
     */
    public function setExpiry($expiry)
    {
        if ($expiry === null) {
            $this->expiry = null;
            return $this;
        }
        if (is_string($expiry)) {
            $expiry = new DateTime($expiry);
        }
        if (!($expiry instanceof DateTimeInterface)) {
            throw new InvalidArgumentException(
                'Invalid "Expiry" value. Must be a date/time string or a DateTime object.'
            );
        }
        $this->expiry = $expiry;
        return $this;
    }

    /**
     * @return DateTimeInterface|null
     */
    public function getExpiry()
    {
        return $this->expiry;
    }

    /**
     * @param DateTimeInterface|string|null $created The date/time at object's creation.
     * @throws InvalidArgumentException If the date/time is invalid.
     * @return self
     */
    public function setCreated($created)
    {
        if ($created === null) {
            $this->created = null;
            return $this;
        }
        if (is_string($created)) {
            $created = new DateTime($created);
        }
        if (!($created instanceof DateTimeInterface)) {
            throw new InvalidArgumentException(
                'Invalid "Created" value. Must be a date/time string or a DateTime object.'
            );
        }
        $this->created = $created;
        return $this;
    }

    /**
     * @return DateTimeInterface|null
     */
    public function getCreated()
    {
        return $this->created;
    }

    /**
     * @param DateTimeInterface|string|null $lastModified The last modified date/time.
     * @throws InvalidArgumentException If the date/time is invalid.
     * @return self
     */
    public function setLastModified($lastModified)
    {
        if ($lastModified === null) {
            $this->lastModified = null;
            return $this;
        }
        if (is_string($lastModified)) {
            $lastModified = new DateTime($lastModified);
        }
        if (!($lastModified instanceof DateTimeInterface)) {
            throw new InvalidArgumentException(
                'Invalid "Last Modified" value. Must be a date/time string or a DateTime object.'
            );
        }
        $this->lastModified = $lastModified;
        return $this;
    }

    /**
     * @return DateTimeInterface|null
     */
    public function getLastModified()
    {
        return $this->lastModified;
    }

    /**
     * Note: the `random_bytes()` function is new to PHP-7. Available in PHP 5 with `compat-random`.
     *
     * @param string $userId The user ID to generate the auth token from.
     * @return self
     */
    public function generate($userId)
    {
        $metadata = $this->metadata();
        $this->setIdent(bin2hex(random_bytes(16)));
        $this->setToken(bin2hex(random_bytes(32)));
        $this->setUserId($userId);
        $this->setExpiry('now + '.$metadata['cookieDuration']);

        return $this;
    }

    /**
     * @return self
     */
    public function sendCookie()
    {
        $metadata = $this->metadata();
        $cookieName = $metadata['cookieName'];
        $value = $this['ident'].';'.$this['token'];
        $expiry = $this['expiry'] ? $this['expiry']->getTimestamp() : null;
        $secure = $metadata['httpsOnly'];

        setcookie($cookieName, $value, $expiry, '', '', $secure);

        return $this;
    }

    /**
     * @return array|null `['ident'=>'', 'token'=>'']
     */
    public function getTokenDataFromCookie()
    {
        $metadata = $this->metadata();
        $cookieName = $metadata['cookieName'];

        if (!isset($_COOKIE[$cookieName])) {
            return null;
        }

        $authCookie = $_COOKIE[$cookieName];
        $vals = explode(';', $authCookie);
        if (!isset($vals[0]) || !isset($vals[1])) {
            return null;
        }

        return [
            'ident' => $vals[0],
            'token' => $vals[1]
        ];
    }

    /**
     * @param mixed  $ident The auth-token identifier.
     * @param string $token The token to validate against.
     * @return mixed The user id. An empty string if no token match.
     */
    public function getUserIdFromToken($ident, $token)
    {
        if (!$this->source()->tableExists()) {
            return '';
        }

        $this->load($ident);
        if (!$this['ident']) {
            $this->logger->warning(sprintf(
                'Auth token not found: "%s"',
                $ident
            ));
            return '';
        }

        // Expired cookie
        $now = new DateTime('now');
        if (!$this['expiry'] || $now > $this['expiry']) {
            $this->logger->warning('Expired auth token');
            $this->delete();
            return '';
        }

        // Validate encrypted token
        if (password_verify($token, $this['token']) !== true) {
            $this->panic();
            $this->delete();
            return '';
        }

        // Success!
        return $this['userId'];
    }

    /**
     * StorableTrait > preSave(): Called automatically before saving the object to source.
     * @return boolean
     */
    protected function preSave()
    {
        parent::preSave();

        if (password_needs_rehash($this->token, PASSWORD_DEFAULT)) {
            $this->token = password_hash($this->token, PASSWORD_DEFAULT);
        }
        $this->setCreated('now');
        $this->setLastModified('now');

        return true;
    }

    /**
     * StorableTrait > preUpdate(): Called automatically before updating the object to source.
     * @param array $properties The properties (ident) set for update.
     * @return boolean
     */
    protected function preUpdate(array $properties = null)
    {
        parent::preUpdate($properties);

        $this->setLastModified('now');

        return true;
    }

    /**
     * Something is seriously wrong: a cookie ident was in the database but with a tampered token.
     *
     * @return void
     */
    protected function panic()
    {
        $this->logger->error(
            'Possible security breach: an authentication token was found in the database but its token does not match.'
        );

        if ($this->userId) {
            $table = $this->source()->table();
            $q = sprintf('
                DELETE FROM
                    `%s`
                WHERE
                    user_id = :userId', $table);
            $this->source()->dbQuery($q, [
                'userId' => $this['userId']
            ]);
        }
    }

    /**
     * Create a new metadata object.
     *
     * @param  array $data Optional metadata to merge on the object.
     * @return AuthTokenMetadata
     */
    protected function createMetadata(array $data = null)
    {
        $class = $this->metadataClass();
        return new $class($data);
    }

    /**
     * Retrieve the class name of the metadata object.
     *
     * @return string
     */
    protected function metadataClass()
    {
        return AuthTokenMetadata::class;
    }
}
