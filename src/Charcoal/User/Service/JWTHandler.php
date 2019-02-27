<?php

namespace Charcoal\User\Service;

use Exception;

// From psr/http-message (PSR-7)
use Psr\Http\Message\ServerRequestInterface as Request;

// From lcobucci/jwt
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\ValidationData;

use Charcoal\User\Config\JWTConfig;

/**
 * Helper class to generate tokens for user and retrieve tokens from request.
 */
class JWTHandler
{
    /**
     * @var Builder
     */
    private $builder;

    /**
     * @var \Lcobucci\JWT\Signer
     */
    private $signer;

    /**
     * @var Parser
     */
    private $parser;

    /**
     * @var ValidationData
     */
    private $validationData;

    /**
     * @var string
     */
    private $privateKey;

    /**
     * @var string
     */
    private $publicKey;

    /**
     * @param JWTConfig $config The auth / JWT configuration.
     */
    public function __construct(JWTConfig $config)
    {
        $this->builder = $this->createBuilder($config);
        $this->signer = $this->createSigner();
        $this->parser = $this->createParser();
        $this->validationData = $this->createValidationData($config);
        $this->privateKey = $this->loadPrivateKey($config);
        $this->publicKey = $this->loadPublicKey($config);
    }

    /**
     * Builds and signs a token with a "uid" claim.
     *
     * @param string $userId The user to generate the token for.
     * @return Token
     */
    public function generateTokenForUserId($userId)
    {
        return $this->builder
            ->set('uid', $userId)
            ->sign($this->signer, $this->privateKey)
            ->getToken();
    }

    /**
     * Retrieves, parses and validates the token from request's HTTP_AUTHORIZATION header.
     *
     * @param Request $request A PSR-7 Request.
     * @throws Exception If there is no authorization headers in request or the token is invalid.
     * @return Token
     */
    public function getTokenFromRequest(Request $request)
    {
        $headers = $request->getHeaders();
        if (!isset($headers['HTTP_AUTHORIZATION'])) {
            throw new Exception(
                'No authorization (HTTP_AUTHORIZATION) in request headers.'
            );
        }
        $bearer = str_replace('Bearer ', '', $headers['HTTP_AUTHORIZATION'][0]);
        $token = $this->parser->parse($bearer);
        if ($this->isTokenValid($token) === false) {
            throw new Exception(
                'Invalid JWT token.'
            );
        }
        return $token;
    }

    /**
     * Validates and verifies a token.
     *
     * @param Token $token The token to validate and verify.
     * @return boolean
     */
    public function isTokenValid(Token $token)
    {
        if ($token->validate($this->validationData) !== true) {
            return false;
        }

        if ($token->verify($this->signer, $this->publicKey) !== true) {
            return false;
        }

        return true;
    }

    /**
     * Retrieves the uid claim (user id) from a token.
     *
     * @param Token $token The Token to load the user from.
     * @throws Exception If the token does not have a user (uid claim) or the user can not be loaded.
     * @return string
     */
    public function getUserIdFromToken(Token $token)
    {
        if ($token->getClaim('uid') === null) {
            throw new Exception(
                'Invalid Token. No user (uid claim).'
            );
        }

        return $token->getClaim('uid');
    }

    /**
     * @param JWTConfig $config The JWT / auth configuration.
     * @return Builder
     */
    private function createBuilder(JWTConfig $config)
    {
        $builder = new Builder();
        $builder
            ->setIssuer($config['issuer'])
            ->setAudience($config['audience'])
            ->setId($config['id'], true)
            ->setIssuedAt(time())
            ->setNotBefore(time())
            ->setExpiration((time() + $config['expiration']));
        return $builder;
    }

    /**
     * @return Parser
     */
    private function createParser()
    {
        return new Parser();
    }

    /**
     * @return \Lcobucci\JWT\Signer
     */
    private function createSigner()
    {
        return new Sha256();
    }

    /**
     * @param JWTConfig $config The JWT / auth configuration.
     * @return ValidationData
     */
    private function createValidationData(JWTConfig $config)
    {
        $validationData = new ValidationData();
        $validationData->setIssuer($config['issuer']);
        $validationData->setAudience($config['audience']);
        $validationData->setId($config['id']);
        return $validationData;
    }

    /**
     * @param JWTConfig $config The JWT / auth configuration.
     * @throws Exception If the key is not set in config or not a string.
     * @return string
     */
    private function loadPrivateKey(JWTConfig $config)
    {
        if (!isset($config['privateKey'])) {
            throw new Exception(
                'JWT authentication configuration requires a private key.'
            );
        }
        $keyFile = $config['privateKey'];
        if (!file_exists($keyFile)) {
            throw new Exception(
                sprintf('JWT private key file "%s" does not exist.', $keyFile)
            );
        }
        return file_get_contents($keyFile);
    }

    /**
     * @param JWTConfig $config The JWT / auth configuration.
     * @throws Exception If the key is not set in config or not a string.
     * @return string
     */
    private function loadPublicKey(JWTConfig $config)
    {
        if (!isset($config['publicKey'])) {
            throw new Exception(
                'JWT authentication configuration requires a public key.'
            );
        }

        $keyFile = $config['publicKey'];
        if (!file_exists($keyFile)) {
            throw new Exception(
                sprintf('JWT public key file "%s" does not exist.', $keyFile)
            );
        }
        return file_get_contents($keyFile);
    }
}
