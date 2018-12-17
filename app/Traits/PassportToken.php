<?php

namespace App\Traits;


use DateTime;
use App\Appuser;
use GuzzleHttp\Psr7\Response;
use Laravel\Passport\Passport;
use Illuminate\Events\Dispatcher;
use League\OAuth2\Server\CryptKey;
use Laravel\Passport\Bridge\Client;
use Laravel\Passport\TokenRepository;
use Laravel\Passport\Bridge\AccessToken;
use Laravel\Passport\Bridge\AccessTokenRepository;
use Laravel\Passport\Bridge\RefreshTokenRepository;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\ResponseTypes\BearerTokenResponse;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException;
/**
 * Trait PassportToken
 *
 * @package App\Trait
 */
trait PassportToken {

	/**
    * 	Generate a new unique identifier.
    *
    * 	@param int $length
    *
    * 	@throws OAuthServerException
    *
    * 	@return string
    */

    private function generateUniqueIdentifier($length = 40) {
    	try {
    		return bin2hex(random_bytes($length));
    	}catch(\TypeError $e) {
    		throw OAuthServerException::serverError("An unexpected error has occured");
    	}catch(\Error $e) {
    		throw OAuthServerException::serverError("An unexpected error has occured");
    	}catch(\Exception $e) {
    		throw OAuthServerException::serverError("Could not generate a random string");
    	}
    }

    private function issueRefreshToken(AccessTokenEntityInterface $accessToken) {
    	$maxGenerationAttempts = 10;
    	$refreshTokenRepository = app(RefreshTokenRepository::class);

    	$refreshToken = $refreshTokenRepository->getNewRefreshToken();
    	$refreshToken->setExpiryDateTime((new \DateTime())->add(Passport::refreshTokensExpireIn()));
    	$refreshToken->setAccessToken($accessToken);

    	while ($maxGenerationAttempts-- > 0) {
    		$refreshToken->setIdentifier($this->generateUniqueIdentifier());
    		try {
    			$refreshTokenRepository->persistNewRefreshToken($refreshToken);
    			return $refreshToken;
    		} catch(UniqueTokenIdentifierConstraintViolationException $e) {
    			if($maxGenerationAttempts === 0) {
    				throw $e;
    			}
    		}
    	}
    }

    protected function createPassportTokenByUser(Appuser $user, $clientId) {
    	$accessToken = new AccessToken($user->id);
    	$accessToken->setIdentifier($this->generateUniqueIdentifier());
    	$accessToken->setClient(new Client($clientId, null, null));
    	$accessToken->setExpiryDateTime((new DateTime())->add(Passport::tokensExpireIn()));

    	$accessTokenRepository = new AccessTokenRepository(new TokenRepository(), new Dispatcher());
    	$accessTokenRepository->persistNewAccessToken($accessToken);
    	$refreshToken = $this->issueRefreshToken($accessToken);

    	return [
    		'access_token' => $accessToken,
    		'refresh_token' => $refreshToken
    	];
    }

    protected function sendBearerTokenResponse($accessToken, $refreshToken) {
    	$response = new BearerTokenResponse();
    	$response->setAccessToken($accessToken);
    	$response->setRefreshToken($refreshToken);

    	$privateKey = new CryptKey('file://'.Passport::keyPath('oauth-private.key'));

    	$response->setPrivateKey($privateKey);
    	$response->setEncryptionKey(app('encrypter')->getKey());

    	return $response->generateHttpResponse(new Response);
    }

    /**
     * 	@param \App\Appuser $user
     * 	@param $clientId
     * 	@param bool $output default = true
     * 	@return array | \League\OAuth2\Server\ResponseTypes\BearerTokenResponse
    */
    protected function getBearerTokenByUser(Appuser $user, $clientId, $output = true) {
    	$passportToken = $this->createPassportTokenByUser($user, $clientId);
    	$bearerToken = $this->sendBearerTokenResponse($passportToken['access_token'], $passportToken['refresh_token']);

    	if(!$output) {
    		$bearerToken = json_decode((string)$bearerToken->getBody(), true);
    	}

    	return $bearerToken;
    }
}