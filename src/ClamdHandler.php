<?php

namespace Zuba\Antivirus;

class ClamdHandler implements AntivirusHandlerInterface
{

    /**
     * @var array
     */
    protected $config;

    /**
     * @param array $config
     * @return void
     */
    public function __construct(array $config)
    {
        if (!empty($config['conf'])) {
            $this->config = $this->parseConf($config['conf']);
        } else {
            $this->config = $config;
        }
    }

    /**
     * Check if the scanner is up and running
     *
     * @return bool
     */
    public function ping()
    {
        return $this->sendCommand('PING');
    }

    /**
     * Return the version number of the scanner
     *
     * @return string
     */
    public function version()
    {
        $version = $this->sendCommand('VERSION');

        return explode('/', $version)[0];
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
        $results = $this->sendCommand("SCAN $path");

        return $this->parseResults($results);
    }

    /**
     * Scan a string for viruses.
     * Returns same array as scan().
     *
     * @param string $stream
     * @return array
     */
    public function streamScan($string)
    {
        // Make sure the stream isn't too big!
        if ($this->config['streamMaxLength'] < $length = strlen($string)) {
            throw new \LengthException("Stream length ($length bytes) exceeds maximum ({$this->config['streamMaxLength']} bytes");
        }

        // Create our data to send to sendCommand
        $stream = $this->createStream();
        fwrite($stream, "zINSTREAM\0");

        // Chunk it into 1KB chunks of data and write to the stream
        $chunks = str_split($string, 1024);
        foreach ($chunks as $chunk) {
            fwrite($stream, pack('N', strlen($chunk)) . "$chunk");
        }

        // All done writing, send our termination
        fwrite($stream, pack('N', 0));

        // Get the results and strip the null termination.
        $results = trim(stream_get_contents($stream), "\0");

        if (strpos($results, 'ERROR') !== false) {
            throw new \LengthException("Stream length ($length bytes) exceeds maximum in clamd.conf");
        }

        return $this->parseResults($results);
    }

    /**
     * Create a stream and send a command to it.
     *
     * @param $command
     * @return string
     */
    protected function sendCommand($command)
    {
        $stream = $this->createStream();
        fwrite($stream, "$command");
        return trim(stream_get_contents($stream));
    }

    /**
     * Create a stream socket client used for sending data to Clamd
     *
     * @return resource
     */
    protected function createStream()
    {
        // Create a stream to send through
        $stream = @stream_socket_client($this->config['socket'], $errno, $errstr);

        if (!$stream) {
            $error = $errno != 0 ? $errstr : 'An unknown error occurred connecting to the ClamAV daemon';
            throw new \RuntimeException($error, $errno);
        }

        return $stream;
    }

    /**
     * Parse out the results of the scan
     *
     * @param $rawResults
     * @return array
     */
    protected function parseResults($rawResults)
    {
        if (!preg_match('~([^:]+):\s(.*?)?\s?(\w+)$~', $rawResults, $match)) {
            return ['file' => '', 'result' => '', 'virus' => ''];
        }

        list(, $file, $virus, $result) = $match;

        $result = $result == 'OK' ? self::RESULT_OK : ($result == 'ERROR' ? self::RESULT_ERROR : self::RESULT_FOUND);

        return compact('file', 'result', 'virus');
    }

    /**
     * Parse a Clamd configuration file
     *
     * @param $conf
     * @return array
     */
    protected function parseConf($conf) {
        if (!is_readable($conf)) {
            throw new \InvalidArgumentException("$conf is not readable.");
        }

        $confContents = file_get_contents($conf);

        $conf = [];

        // Try for a ip and port first
        if (preg_match('~TCPAddr (.*)~', $confContents, $matchAddr)
            && preg_match('~TCPSocket (\d+)~', $confContents, $matchPort)) {
            $conf['socket'] = "tcp://$matchAddr[1]:$matchPort[1]";
        }

        // We prefer unix sockets if possible though
        if (preg_match('~LocalSocket (.*)~', $confContents, $matchSocket)) {
            $conf['socket'] = "unix://$matchSocket[1]";
        }

        // Max Stream length
        preg_match('~StreamMaxLength (\d+)~', $confContents, $matchMaxLength);
        $length = !empty($matchMaxLength) ? (int) $matchMaxLength[1] : 10;
        $conf['streamMaxLength'] = $length * 1024 * 1024;

        return $conf;
    }
}
