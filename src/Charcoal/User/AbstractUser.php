<?php

namespace Charcoal\User;

use DateTime;
use DateTimeInterface;
use Exception;
use InvalidArgumentException;

// From 'charcoal-factory'
use Charcoal\Factory\FactoryInterface;

// From 'charcoal-core'
use Charcoal\Validator\ValidatorInterface;

// From 'charcoal-config'
use Charcoal\Config\ConfigurableInterface;
use Charcoal\Config\ConfigurableTrait;

// From 'charcoal-object'
use Charcoal\Object\Content;

/**
 * Full implementation, as abstract class, of the `UserInterface`.
 */
abstract class AbstractUser extends Content implements
    UserInterface,
    ConfigurableInterface
{
    use ConfigurableTrait;

    /**
     * @var UserInterface $authenticatedUser
     */
    protected static $authenticatedUser;

    /**
     * The email address should be unique and mandatory.
     *
     * It is also used as the login name.
     *
     * @var string
     */
    private $email;

    /**
     * The password is stored encrypted in the (database) storage.
     *
     * @var string|null
     */
    private $password;

    /**
     * The display name serves as a human-readable identifier for the user.
     *
     * @var string|null
     */
    private $displayName;

    /**
     * Roles define a set of tasks a user is allowed or denied from performing.
     *
     * @var string[]
     */
    private $roles = [];

    /**
     * The timestamp of the latest (successful) login.
     *
     * @var DateTimeInterface|null
     */
    private $lastLoginDate;

    /**
     * The IP address during the latest (successful) login.
     *
     * @var string|null
     */
    private $lastLoginIp;

    /**
     * The timestamp of the latest password change.
     *
     * @var DateTimeInterface|null
     */
    private $lastPasswordDate;

    /**
     * The IP address during the latest password change.
     *
     * @var string|null
     */
    private $lastPasswordIp;

    /**
     * Tracks the password reset token.
     *
     * If the token is set (not empty), then the user should be prompted
     * to reset his password after login / enter the token to continue.
     *
     * @var string|null
     */
    private $loginToken = '';

    /**
     * Structure
     *
     * Get the user preferences
     *
     * @var array|mixed
     */
    private $preferences;

    /**
     * @param  string $email The user email.
     * @throws InvalidArgumentException If the email is not a string.
     * @return self
     */
    public function setEmail($email)
    {
        if (!is_string($email)) {
            throw new InvalidArgumentException(
                'Set user email: Email must be a string'
            );
        }

        $this->email = $email;

        return $this;
    }

    /**
     * @return string
     */
    public function getEmail()
    {
        return $this->email;
    }

    /**
     * @param  string|null $password The user password. Encrypted in storage.
     * @throws InvalidArgumentException If the password is not a string (or null, to reset).
     * @return self
     */
    public function setPassword($password)
    {
        if ($password === null) {
            $this->password = $password;
        } elseif (is_string($password)) {
            $this->password = $password;
        } else {
            throw new InvalidArgumentException(
                'Set user password: Password must be a string'
            );
        }

        return $this;
    }

    /**
     * @return string|null
     */
    public function getPassword()
    {
        return $this->password;
    }

    /**
     * @param  string|null $name The user's display name.
     * @return self
     */
    public function setDisplayName($name)
    {
        $this->displayName = $name;

        return $this;
    }

    /**
     * @return string|null
     */
    public function getDisplayName()
    {
        return $this->displayName;
    }

    /**
     * @param  string|string[]|null $roles The ACL roles this user belongs to.
     * @throws InvalidArgumentException If the roles argument is invalid.
     * @return self
     */
    public function setRoles($roles)
    {
        if (empty($roles) && !is_numeric($roles)) {
            $this->roles = [];
            return $this;
        }

        if (is_string($roles)) {
            $roles = explode(',', $roles);
        }

        if (!is_array($roles)) {
            throw new InvalidArgumentException(
                'Roles must be a comma-separated string or an array'
            );
        }

        $this->roles = array_filter(array_map('trim', $roles), 'strlen');

        return $this;
    }

    /**
     * @return string[]
     */
    public function getRoles()
    {
        return $this->roles;
    }

    /**
     * @param  string|DateTimeInterface|null $lastLoginDate The last login date.
     * @throws InvalidArgumentException If the ts is not a valid date/time.
     * @return self
     */
    public function setLastLoginDate($lastLoginDate)
    {
        if ($lastLoginDate === null) {
            $this->lastLoginDate = null;
            return $this;
        }

        if (is_string($lastLoginDate)) {
            try {
                $lastLoginDate = new DateTime($lastLoginDate);
            } catch (Exception $e) {
                throw new InvalidArgumentException(sprintf(
                    'Invalid login date (%s)',
                    $e->getMessage()
                ), 0, $e);
            }
        }

        if (!($lastLoginDate instanceof DateTimeInterface)) {
            throw new InvalidArgumentException(
                'Invalid "Last Login Date" value. Must be a date/time string or a DateTime object.'
            );
        }

        $this->lastLoginDate = $lastLoginDate;

        return $this;
    }

    /**
     * @return DateTimeInterface|null
     */
    public function getLastLoginDate()
    {
        return $this->lastLoginDate;
    }

    /**
     * @param  string|integer|null $ip The last login IP address.
     * @throws InvalidArgumentException If the IP is not an IP string, an integer, or null.
     * @return self
     */
    public function setLastLoginIp($ip)
    {
        if ($ip === null) {
            $this->lastLoginIp = null;
            return $this;
        }

        if (is_int($ip)) {
            $ip = long2ip($ip);
        }

        if (!is_string($ip)) {
            throw new InvalidArgumentException(
                'Invalid IP address'
            );
        }

        $this->lastLoginIp = $ip;

        return $this;
    }

    /**
     * Get the last login IP in x.x.x.x format
     *
     * @return string|null
     */
    public function getLastLoginIp()
    {
        return $this->lastLoginIp;
    }

    /**
     * @param  string|DateTimeInterface|null $lastPasswordDate The last password date.
     * @throws InvalidArgumentException If the passsword date is not a valid DateTime.
     * @return self
     */
    public function setLastPasswordDate($lastPasswordDate)
    {
        if ($lastPasswordDate === null) {
            $this->lastPasswordDate = null;
            return $this;
        }

        if (is_string($lastPasswordDate)) {
            try {
                $lastPasswordDate = new DateTime($lastPasswordDate);
            } catch (Exception $e) {
                throw new InvalidArgumentException(sprintf(
                    'Invalid last password date (%s)',
                    $e->getMessage()
                ), 0, $e);
            }
        }

        if (!($lastPasswordDate instanceof DateTimeInterface)) {
            throw new InvalidArgumentException(
                'Invalid "Last Password Date" value. Must be a date/time string or a DateTime object.'
            );
        }

        $this->lastPasswordDate = $lastPasswordDate;

        return $this;
    }

    /**
     * @return DateTimeInterface|null
     */
    public function getLastPasswordDate()
    {
        return $this->lastPasswordDate;
    }

    /**
     * @param  integer|string|null $ip The last password IP.
     * @throws InvalidArgumentException If the IP is not null, an integer or an IP string.
     * @return self
     */
    public function setLastPasswordIp($ip)
    {
        if ($ip === null) {
            $this->lastPasswordIp = null;
            return $this;
        }

        if (is_int($ip)) {
            $ip = long2ip($ip);
        }

        if (!is_string($ip)) {
            throw new InvalidArgumentException(
                'Invalid IP address'
            );
        }

        $this->lastPasswordIp = $ip;

        return $this;
    }

    /**
     * Get the last password change IP in x.x.x.x format
     *
     * @return string|null
     */
    public function getLastPasswordIp()
    {
        return $this->lastPasswordIp;
    }

    /**
     * @param  string|null $token The login token.
     * @throws InvalidArgumentException If the token is not a string.
     * @return self
     */
    public function setLoginToken($token)
    {
        if ($token === null) {
            $this->loginToken = null;
            return $this;
        }

        if (!is_string($token)) {
            throw new InvalidArgumentException(
                'Login Token must be a string'
            );
        }

        $this->loginToken = $token;

        return $this;
    }

    /**
     * @return string|null
     */
    public function getLoginToken()
    {
        return $this->loginToken;
    }

    /**
     * @param array|mixed $preferences Preferences for AbstractUser.
     * @return self
     */
    public function setPreferences($preferences)
    {
        $this->preferences = $preferences;

        return $this;
    }

    /**
     * @return array|mixed
     */
    public function preferences()
    {
        return $this->preferences;
    }

    /**
     * @throws Exception If trying to save a user to session without a ID.
     * @return self
     */
    public function saveToSession()
    {
        if (!$this->id()) {
            throw new Exception(
                'Can not set auth user; no user ID'
            );
        }

        $_SESSION[static::sessionKey()] = $this->id();

        return $this;
    }

    /**
     * Log in the user (in session)
     *
     * Called when the authentication is successful.
     *
     * @return boolean Success / Failure
     */
    public function login()
    {
        if (!$this->id()) {
            return false;
        }

        $this->setLastLoginDate('now');
        $ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '';
        if ($ip) {
            $this->setLastLoginIp($ip);
        }

        $this->update([
            'last_login_ip',
            'last_login_date'
        ]);

        $this->saveToSession();

        return true;
    }

    /**
     * Empties the session var associated to the session key.
     *
     * @return boolean Logged out or not.
     */
    public function logout()
    {
        // Irrelevant call...
        if (!$this->id()) {
            return false;
        }

        $key = static::sessionKey();

        $_SESSION[$key] = null;
        unset($_SESSION[$key], static::$authenticatedUser[$key]);

        return true;
    }

    /**
     * Reset the password.
     *
     * Encrypt the password and re-save the object in the database.
     * Also updates the last password date & ip.
     *
     * @param string $plainPassword The plain (non-encrypted) password to reset to.
     * @throws InvalidArgumentException If the plain password is not a string.
     * @return self
     */
    public function resetPassword($plainPassword)
    {
        if (!is_string($plainPassword)) {
            throw new InvalidArgumentException(
                'Can not change password: password is not a string.'
            );
        }

        $hash = password_hash($plainPassword, PASSWORD_DEFAULT);
        $this->setPassword($hash);

        $this->setLastPasswordDate('now');
        $ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '';
        if ($ip) {
            $this->setLastPasswordIp($ip);
        }

        if ($this->id()) {
            $this->update([
                'password',
                'last_password_date',
                'last_password_ip'
            ]);
        }

        return $this;
    }

    /**
     * Get the currently authenticated user (from session)
     *
     * Return null if there is no current user in logged into
     *
     * @param  FactoryInterface $factory The factory to create the user object with.
     * @throws Exception If the user from session is invalid.
     * @return UserInterface|null
     */
    public static function getAuthenticated(FactoryInterface $factory)
    {
        $key = static::sessionKey();

        if (isset(static::$authenticatedUser[$key])) {
            return static::$authenticatedUser[$key];
        }

        if (!isset($_SESSION[$key])) {
            return null;
        }

        $userId = $_SESSION[$key];
        if (!$userId) {
            return null;
        }

        $userClass = get_called_class();
        $user = $factory->create($userClass);
        $user->load($userId);

        // Inactive users can not authenticate
        if (!$user['id'] || !$user['email'] || !$user['active']) {
            return null;
        }

        static::$authenticatedUser[$key] = $user;

        return $user;
    }



    // Extends Charcoal\Validator\ValidatableTrait
    // =========================================================================

    /**
     * Validate the model.
     *
     * @see   \Charcoal\Validator\ValidatorInterface
     * @param ValidatorInterface $v Optional. A custom validator object to use for validation. If null, use object's.
     * @return boolean
     */
    public function validate(ValidatorInterface &$v = null)
    {
        $result = parent::validate($v);
        $objType = self::objType();
        $previousModel = $this->modelFactory()->create($objType)->load($this->id());

        $email = $this['email'];
        if (empty($email)) {
            $this->validator()->error(
                'Email is required.',
                'email'
            );
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $this->validator()->error(
                'Email format is incorrect.',
                'email'
            );
        /** Check if updating/changing email. */
        } elseif ($previousModel['email'] !== $email) {
            $existingModel = $this->modelFactory()->create($objType)->loadFrom('email', $email);
            /** Check for existing user with given email. */
            if (!empty($existingModel->id())) {
                $this->validator()->error(
                    'This email is not available.',
                    'email'
                );
            }
        }

        return count($this->validator()->errorResults()) === 0 && $result;
    }
}
