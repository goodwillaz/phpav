<?php

namespace Gwaz\Antivirus;

class Scanner implements ScannerInterface
{

    /**
     * @var AntivirusHandlerInterface
     */
    protected $handler;

    /**
     * @var array
     */
    protected $last;

    /**
     * @param type AntivirusHandlerInterface $handler
     */
    public function __construct(AntivirusHandlerInterface $handler)
    {
        $this->handler = $handler;
    }

    /**
     * Return if the backend scanner is up and running
     *
     * @return bool
     */
    public function alive()
    {
        return $this->handler->ping() === 'PONG';
    }

    /**
     * Return the version of the backend scanner
     *
     * @return string
     */
    public function version()
    {
        return $this->handler->version();
    }

    /**
     * Scan the given file.
     * Returns an array containing the file and it's result
     *
     * @param string $file
     * @return array
     * @throws \InvalidArgumentException
     */
    public function scan($file)
    {
        if (is_dir($file)) {
            throw new \InvalidArgumentException('Scanner::scan() expects parameter 1 to be a file, directory given.');
        }

        if (!is_readable($file)) {
            throw new \InvalidArgumentException('Scanner::scan() must be passed a file that is readable.');
        }

        return $this->last = $this->handler->scan($file);
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
        return $this->last = $this->handler->streamScan($stream);
    }

    /**
     * Was the last scan a clean scan?
     *
     * @return bool
     * @throws \BadMethodCallException
     */
    public function clean()
    {
        if (null === $this->last) {
            throw new \BadMethodCallException('No previous scan to report on.');
        }

        return $this->last['result'] === AntivirusHandlerInterface::RESULT_OK;
    }

    /**
     * Return the last scan's results
     *
     * @return array
     */
    public function last()
    {
        return $this->last;
    }
}
