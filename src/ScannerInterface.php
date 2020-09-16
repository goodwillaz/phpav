<?php

namespace Zuba\Antivirus;

interface ScannerInterface
{
    /**
     * Return if the backend scanner is up and running
     *
     * @return bool
     */
    public function alive();

    /**
     * Return the version of the backend scanner
     *
     * @return string
     */
    public function version();

    /**
     * Scan the given file.
     * Returns an array containing the file and it's result
     *
     * @param string $path
     * @return array
     */
    public function scan($path);

    /**
     * Scan a string for viruses.
     * Returns an array with the result as a key.
     *
     * @param string $stream
     * @return array
     */
    public function streamScan($stream);

    /**
     * Was the last scan a clean scan?
     *
     * @return bool
     */
    public function clean();

    /**
     * Return the last scan's results
     *
     * @return array
     */
    public function last();
}
