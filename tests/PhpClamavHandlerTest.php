<?php

class PhpClamavHandlerTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var \Zuba\Antivirus\PhpClamavHandler
     */
    protected $handler;

    public function setUp()
    {
        if (!extension_loaded('clamav') && !(ini_get('enable_dl') && dl('clamav.so'))) {
            $this->markTestSkipped('php-clamav not installed');
        }

        $this->handler = new \Zuba\Antivirus\PhpClamavHandler;
    }

    public function testPing()
    {
        $this->assertEquals('PONG', $this->handler->ping());
    }

    public function testVersion()
    {
        $this->assertEquals('ClamAV 0.98.1', $this->handler->version());
    }

    public function testVirusScan()
    {
        $result = $this->handler->scan(__DIR__ . '/fixtures/eicar.txt');
        $this->assertEquals(\Zuba\Antivirus\AntivirusHandlerInterface::RESULT_FOUND, $result['result']);
        $this->assertEquals('Eicar-Test-Signature', $result['virus']);
    }

    public function testOkScan()
    {
        $result = $this->handler->scan(__DIR__ . '/fixtures/ok.txt');
        $this->assertEquals(\Zuba\Antivirus\AntivirusHandlerInterface::RESULT_OK, $result['result']);
    }

    public function testErrorScan()
    {
        $result = $this->handler->scan(__DIR__ . '/fixtures/noexist.txt');
        $this->assertEquals(\Zuba\Antivirus\AntivirusHandlerInterface::RESULT_ERROR, $result['result']);
        $this->assertEquals('CL_EOPEN error', $result['virus']);
    }

    public function testOkStream()
    {
        $result = $this->handler->streamScan('I am some good text');
        $this->assertEquals(\Zuba\Antivirus\AntivirusHandlerInterface::RESULT_OK, $result['result']);
        $this->assertEquals('stream', $result['file']);
        $this->assertEmpty($result['virus']);
    }

    public function testVirusStream()
    {
        $result = $this->handler->streamScan('X5O!P%@AP[4\PZX54(P^)7CC)7}$' . 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*');
        $this->assertEquals(\Zuba\Antivirus\AntivirusHandlerInterface::RESULT_FOUND, $result['result']);
        $this->assertEquals('Eicar-Test-Signature', $result['virus']);
    }
}
