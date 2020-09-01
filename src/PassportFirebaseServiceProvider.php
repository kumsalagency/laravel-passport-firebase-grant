<?php


namespace KumsalAgency\Passport\Firebase;


use Illuminate\Support\ServiceProvider;
use KumsalAgency\Passport\Firebase\Bridge\FirebaseGrant;
use KumsalAgency\Passport\Firebase\Bridge\UserRepository;
use Laravel\Passport\Bridge\RefreshTokenRepository;
use Laravel\Passport\Passport;
use League\OAuth2\Server\AuthorizationServer;

class PassportFirebaseServiceProvider extends ServiceProvider
{

    /**
     * Register any application services.
     *
     * @return void
     */
    public function register()
    {

    }

    /**
     * Bootstrap any application services.
     *
     * @return void
     */
    public function boot()
    {
        app(AuthorizationServer::class)->enableGrantType(
            $this->makeFirebaseGrant(), Passport::tokensExpireIn()
        );
    }

    /**
     * @return FirebaseGrant
     */
    protected function makeFirebaseGrant()
    {
        $firebaseGrant = new FirebaseGrant(
            $this->app->make(UserRepository::class),
            $this->app->make(RefreshTokenRepository::class)
        );

        $firebaseGrant->setRefreshTokenTTL(Passport::refreshTokensExpireIn());

        return $firebaseGrant;
    }
}