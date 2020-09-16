<?php

namespace Zuba\Antivirus;

class PhpClamavHandler implements AntivirusHandlerInterface
{

    public function __construct()
    {
        if (!extension_loaded('clamav')) {
            throw new \InvalidArgumentException('php-clamav is not installed');
        }
    }
    /**
     * Check if the scanner is up and running
     *
     * @return bool
     */
    public function ping()
    {
        return 'PONG';
    }

    /**
     * Return the version number of the scanner
     *
     * @return string
     */
    public function version()
    {
        return 'ClamAV ' . cl_version();
    }

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
    public function scan($path)
    {
        $code = @cl_scanfile($path, $virus);
        $result = $code == CL_CLEAN ? self::RESULT_OK : ($code == CL_VIRUS ? self::RESULT_FOUND : self::RESULT_ERROR);
        return [
            'file' => $path,
            'result' => $result,
            'virus' => $code == CL_VIRUS || $code == CL_CLEAN ? $virus : cl_pretcode($code),
        ];
    }

    /**
     * Scan a string for viruses.
     * Returns an array with the result as a key.
     *
     * @param string $stream
     * @return array
     */
    public function streamScan($stream)
    {
        // Save the stream to a temporary file for scanning
        $file = tempnam(sys_get_temp_dir(), 'VIR');

        file_put_contents($file, $stream);

        $results = $this->scan($file);

        $results['file'] = 'stream';

        return $results;
    }
}
