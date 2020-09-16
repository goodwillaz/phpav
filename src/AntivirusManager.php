<?php

namespace Gwaz\Antivirus;

use \Illuminate\Support\Manager;

class AntivirusManager extends Manager
{
    /**
     * Call a custom driver creator.
     *
     * @param  string  $driver
     * @return mixed
     */
    protected function callCustomCreator($driver)
    {
        $custom = parent::callCustomCreator($driver);

        if ($custom instanceof ScannerInterface) return $custom;

        return $this->buildScanner($custom);
    }

    protected function createClamdDriver()
    {
        return $this->buildScanner(new ClamdHandler($this->app['config']['antivirus::clamd']));
    }

    protected function createPhpClamavDriver()
    {
        return $this->buildScanner(new PhpClamavHandler());
    }

    protected function buildScanner($handler)
    {
        return new Scanner($handler);
    }

    /**
     * Get the default antivirus driver
     *
     * @return string
     */
    public function getDefaultDriver()
    {
        return $this->app['config']['antivirus::driver'];
    }

    /**
     * Set the default authentication driver name.
     *
     * @param  string  $name
     * @return void
     */
    public function setDefaultDriver($name)
    {
        $this->app['config']['antivirus::driver'] = $name;
    }

    /**
     * Return whether or not this is actually enabled
     *
     * @return bool
     */
    public function enabled()
    {
        return $this->app['config']['antivirus::enabled'] == true;
    }
}
