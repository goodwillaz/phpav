<?php

namespace Zuba\Antivirus;

use Illuminate\Foundation\AliasLoader;
use Illuminate\Support\ServiceProvider;

class AntivirusServiceProvider extends ServiceProvider {

    /**
     * Indicates if loading of the provider is deferred.
     *
     * @var bool
     */
    protected $defer = false;

    /**
     * Bootstrap the application events.
     *
     * @return void
     */
    public function boot()
    {
        $this->package('zuba/antivirus', null, __DIR__);

        AliasLoader::getInstance(['Antivirus' => '\Zuba\Antivirus\Support\Facades\Antivirus']);
    }

    /**
     * Register the service provider.
     *
     * @return void
     */
    public function register()
    {
        $this->registerAntivirusManager();
    }

    /**
     *  Register the Antivirus Manager
     */
    protected function registerAntivirusManager()
    {
        $this->app->bindShared('avscanner', function ($app) {
            return new AntivirusManager($app);
        });
    }

    /**
     * Get the services provided by the provider.
     *
     * @return array
     */
    public function provides()
    {
        return ['avscanner'];
    }

}
