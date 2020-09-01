<?php

namespace KumsalAgency\Passport\Firebase\Bridge;

use Firebase\Auth\Token\Exception\InvalidToken;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;
use Laravel\Passport\Bridge\User;
use RuntimeException;

class UserRepository implements UserRepositoryInterface
{
    /**
     * {@inheritdoc}
     */
    public function getUserEntityByUserCredentials($username, $password, $grantType, ClientEntityInterface $clientEntity)
    {
        $provider = $clientEntity->provider ?: config('auth.guards.api.provider');

        if (is_null($model = config('auth.providers.'.$provider.'.model'))) {
            throw new RuntimeException('Unable to determine authentication model from configuration.');
        }

        if (method_exists($model, 'findAndValidateForPassport')) {
            $user = (new $model)->findAndValidateForPassport($username, $password);

            if (! $user) {
                return;
            }

            return new User($user->getAuthIdentifier());
        }

        if (method_exists($model, 'findForPassport')) {
            $user = (new $model)->findForPassport($username);
        } else {
            $user = (new $model)->where('uid', $username)->first();
        }

        if (! $user) {
            return;
        } elseif (method_exists($user, 'validateForPassportFirebaseGrant')) {
            if (! $user->validateForPassportPasswordGrant($password)) {
                return;
            }
        } else {

            $auth = app('firebase.auth');

            try {
                $verifiedIdToken = $auth->verifyIdToken($password);

            } catch (\InvalidArgumentException $exception) {

                return response()->json([
                    'message' => 'Unauthorized - Can\'t parse the token: ' . $exception->getMessage()
                ], 401);

            } catch (InvalidToken $exception) {

                return response()->json([
                    'message' => 'Unauthorized - Token is invalide: ' . $exception->getMessage()
                ], 401);
            }

            if ($verifiedIdToken->getClaim('sub') != $username){
                return;
            }
        }


        return new User($user->getAuthIdentifier());
    }
}
