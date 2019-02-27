<?php

namespace Charcoal\User;

// From 'charcoal-object'
use Charcoal\Object\ContentInterface;

/**
 * User Interface, based on charcoal/object/content-interface.
 */
interface UserInterface extends ContentInterface
{
    /**
     * @return string
     */
    public static function sessionKey();

    /**
     * Force a lowercase username
     *
     * @param string $username The username (also the login name).
     @return self
     */
    public function setUsername($username);

    /**
     * The username is also used as login name and main identifier (key).
     *
     * @return string
     */
    public function username();

    /**
     * @param string $email The user email.
     @return self
     */
    public function setEmail($email);

    /**
     * @return string
     */
    public function email();

    /**
     * @param string|null $password The user password. Encrypted in storage.
     @return self
     */
    public function setPassword($password);

    /**
     * @return string
     */
    public function password();

    /**
     * @param string|string[]|null $roles The ACL roles this user belongs to.
     * @throws \InvalidArgumentException If the roles argument is invalid.
     @return self
     */
    public function setRoles($roles);

    /**
     * @return string[]
     */
    public function roles();

    /**
     * @param boolean $active The active flag.
     @return self
     */
    public function setActive($active);

    /**
     * @return boolean
     */
    public function active();

    /**
     * @param string|\DateTimeInterface $ts The last login date.
     @return self
     */
    public function setLastLoginDate($ts);

    /**
     * @return \DateTimeInterface|null
     */
    public function lastLoginDate();

    /**
     * @param string|integer|null $ip The last login IP address.
     @return self
     */
    public function setLastLoginIp($ip);

    /**
     * Get the last login IP in x.x.x.x format
     * @return string
     */
    public function lastLoginIp();

    /**
     * @param string|\DateTimeInterface $ts The last password date.
     @return self
     */
    public function setLastPasswordDate($ts);

    /**
     * @return \DateTimeInterface|null
     */
    public function lastPasswordDate();

    /**
     * @param integer|string|null $ip The last password IP.
     @return self
     */
    public function setLastPasswordIp($ip);

    /**
     * Get the last password change IP in x.x.x.x format.
     *
     * @return string
     */
    public function lastPasswordIp();

    /**
     * @param string $token The login token.
     @return self
     */
    public function setLoginToken($token);

    /**
     * @return string
     */
    public function loginToken();

    /**
     * Reset the password.
     *
     * Encrypt the password and re-save the object in the database.
     * Also updates the last password date & ip.
     *
     * @param string $plainPassword The plain (non-encrypted) password to reset to.
     @return self
     */
    public function resetPassword($plainPassword);

    /**
     * Structure
     *
     * Get the user preferences
     *
     * @return array|mixed
     */
    public function preferences();
}
