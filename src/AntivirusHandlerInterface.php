<?php

namespace Gwaz\Antivirus;

interface AntivirusHandlerInterface
{
    const RESULT_OK    = 1;
    const RESULT_FOUND = 2;
    const RESULT_ERROR = 3;

    /**
     * Check if the scanner is up and running
     *
     * @return bool
     */
    public function ping();

    /**
     * Return the version number of the scanner
     *
     * @return string
     */
    public function version();

    /**
     * Scan the given file.  Returns an array of information
     *
     * Array for a particular entry should be of the following format
     * [
     *  'file' => <file scanned>,
     *  'result' => <RESULT_ERROR|OK|FOUND>
     *  'virus' => <if RESULT_FOUND, virus name, if RESULT_ERROR, error message>
     * ]
     *
     * @param string $path
     * @return array
     */
    public function scan($path);

    /**
     * Scan a string for viruses.
     * Returns same array as scan().
     *
     * @param string $stream
     * @return array
     */
    public function streamScan($stream);
}
