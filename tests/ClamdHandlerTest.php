<?php

class ClamdHandlerTest extends \PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        if (!file_exists('/var/run/clamav/clamd.ctl')) {
            $this->markTestSkipped("Clamd is not running");
        }
    }

    public function testPing()
    {
        $handler = new \Zuba\Antivirus\ClamdHandler(['socket' => 'unix:///var/run/clamav/clamd.ctl']);
        $this->assertEquals('PONG', $handler->ping());
    }

    public function testVersion()
    {
        $handler = new \Zuba\Antivirus\ClamdHandler(['socket' => 'unix:///var/run/clamav/clamd.ctl']);
        $this->assertEquals('ClamAV 0.98.1', $handler->version());
    }

    public function testVirusScan()
    {
        $handler = new \Zuba\Antivirus\ClamdHandler(['socket' => 'unix:///var/run/clamav/clamd.ctl']);
        $result = $handler->scan(__DIR__ . '/fixtures/eicar.txt');
        $this->assertEquals(\Zuba\Antivirus\AntivirusHandlerInterface::RESULT_FOUND, $result['result']);
        $this->assertEquals('Eicar-Test-Signature', $result['virus']);
    }

    public function testOkScan()
    {
        $handler = new \Zuba\Antivirus\ClamdHandler(['socket' => 'unix:///var/run/clamav/clamd.ctl']);
        $result = $handler->scan(__DIR__ . '/fixtures/ok.txt');
        $this->assertEquals(\Zuba\Antivirus\AntivirusHandlerInterface::RESULT_OK, $result['result']);
    }

    public function testErrorScan()
    {
        $handler = new \Zuba\Antivirus\ClamdHandler(['socket' => 'unix:///var/run/clamav/clamd.ctl']);
        $result = $handler->scan(__DIR__ . '/fixtures/noexist.txt');
        $this->assertEquals(\Zuba\Antivirus\AntivirusHandlerInterface::RESULT_ERROR, $result['result']);
        $this->assertEquals('lstat() failed: No such file or directory.', $result['virus']);
    }

    public function testOkStream()
    {
        $handler = new \Zuba\Antivirus\ClamdHandler([
                'socket' => 'unix:///var/run/clamav/clamd.ctl', 'streamMaxLength' => 26214400
            ]);
        $result = $handler->streamScan('I am some good text');
        $this->assertEquals(\Zuba\Antivirus\AntivirusHandlerInterface::RESULT_OK, $result['result']);
        $this->assertEquals('stream', $result['file']);
        $this->assertEmpty($result['virus']);
    }

    public function testVirusStream()
    {
        $handler = new \Zuba\Antivirus\ClamdHandler([
                'socket' => 'unix:///var/run/clamav/clamd.ctl', 'streamMaxLength' => 26214400
            ]);
        $result = $handler->streamScan('X5O!P%@AP[4\PZX54(P^)7CC)7}$' . 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*');
        $this->assertEquals(\Zuba\Antivirus\AntivirusHandlerInterface::RESULT_FOUND, $result['result']);
        $this->assertEquals('Eicar-Test-Signature', $result['virus']);
    }

    public function testConfFile()
    {
        $handler = new \Zuba\Antivirus\ClamdHandler(['conf' => '/etc/clamav/clamd.conf']);
        $this->assertEquals('PONG', $handler->ping());
    }

    public function testInvalidConfFile()
    {
        $this->setExpectedException('\InvalidArgumentException');
        new \Zuba\Antivirus\ClamdHandler(['conf' => __DIR__ . '/fixtures/IDontExist']);
    }
}
