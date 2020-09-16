<?php

class ClamdHandlerTest extends \PHPUnit_Framework_TestCase
{
    protected $socket;

    public function setUp()
    {
        if (!$this->socket = getenv('CLAMD_SOCKET')) {
            $this->markTestSkipped("Clamd is not running");
        }
    }

    public function testPing()
    {
        $handler = new \Gwaz\Antivirus\ClamdHandler(['socket' => $this->socket]);
        $this->assertEquals('PONG', $handler->ping());
    }

    public function testVersion()
    {
        $handler = new \Gwaz\Antivirus\ClamdHandler(['socket' => $this->socket]);
        $this->assertRegExp('~^ClamAV \d+\.\d+\.\d+$~', $handler->version());
    }

    public function testOkScan()
    {
        $handler = new \Gwaz\Antivirus\ClamdHandler(['socket' => $this->socket, 'streamMaxLength' => 26214400]);
        $result = $handler->scan(__DIR__ . '/fixtures/ok.txt');
        $this->assertEquals(\Gwaz\Antivirus\AntivirusHandlerInterface::RESULT_OK, $result['result']);
    }

    public function testOkStream()
    {
        $handler = new \Gwaz\Antivirus\ClamdHandler([
                'socket' => $this->socket, 'streamMaxLength' => 26214400
            ]);
        $result = $handler->streamScan('I am some good text');
        $this->assertEquals(\Gwaz\Antivirus\AntivirusHandlerInterface::RESULT_OK, $result['result']);
        $this->assertEquals('stream', $result['file']);
        $this->assertEmpty($result['virus']);
    }

    public function testVirusStream()
    {
        $handler = new \Gwaz\Antivirus\ClamdHandler([
                'socket' => $this->socket, 'streamMaxLength' => 26214400
            ]);
        $result = $handler->streamScan('X5O!P%@AP[4\PZX54(P^)7CC)7}$' . 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*');
        $this->assertEquals(\Gwaz\Antivirus\AntivirusHandlerInterface::RESULT_FOUND, $result['result']);
        $this->assertEquals('Eicar-Test-Signature', $result['virus']);
    }

    public function testConfFile()
    {
        $handler = new \Gwaz\Antivirus\ClamdHandler(['conf' => __DIR__ . '/fixtures/clamd.conf']);
        $this->assertEquals('PONG', $handler->ping());
    }

    /**
     * @expectedException \InvalidArgumentException
     */
    public function testInvalidConfFile()
    {
        new \Gwaz\Antivirus\ClamdHandler(['conf' => __DIR__ . '/fixtures/IDontExist.conf']);
    }
}
