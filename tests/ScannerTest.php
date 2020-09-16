<?php
/**
 * Author: MZuba
 * Date: 8/3/2017
 * Time: 1:35 PM
 */

use Gwaz\Antivirus\AntivirusHandlerInterface;
use Gwaz\Antivirus\Scanner;
use Mockery as m;

class ScannerTest extends PHPUnit_Framework_TestCase
{
    public function testAlive()
    {
        $scanner = new Scanner($handler = m::mock(AntivirusHandlerInterface::class));
        $handler->shouldReceive('ping')->andReturn('PONG');
        $this->assertTrue($scanner->alive());
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Scanner::scan() expects parameter 1 to be a file, directory given.
     */
    public function testScanDir()
    {
        $scanner = new Scanner(m::mock(AntivirusHandlerInterface::class));
        $scanner->scan(__DIR__);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Scanner::scan() must be passed a file that is readable.
     */
    public function testScanFileDoesntExist()
    {
        $scanner = new Scanner(m::mock(AntivirusHandlerInterface::class));
        $scanner->scan(__DIR__ . '/fixtures/dontexist.virus');
    }

    public function testScan()
    {
        $scanner = new Scanner($handler = m::mock(AntivirusHandlerInterface::class));
        $handler->shouldReceive('scan')->andReturn('foo');
        $this->assertEquals('foo', $scanner->scan(__DIR__ . '/fixtures/ok.txt'));
    }

    public function testHasLastResult()
    {
        $scanner = new Scanner($handler = m::mock(AntivirusHandlerInterface::class));
        $handler->shouldReceive('scan')->andReturn('foo');
        $scanner->scan(__DIR__ . '/fixtures/ok.txt');
        $this->assertEquals('foo', $scanner->last());
    }

    /**
     * @expectedException \BadMethodCallException
     * @expectedExceptionMessage No previous scan to report on.
     */
    public function testCleanWithNoScan()
    {
        $scanner = new Scanner(m::mock(AntivirusHandlerInterface::class));
        $scanner->clean();
    }

    public function testCleanAfterScan()
    {
        $scanner = new Scanner($handler = m::mock(AntivirusHandlerInterface::class));
        $handler->shouldReceive('scan')->andReturn(['result' => AntivirusHandlerInterface::RESULT_OK]);
        $scanner->scan(__DIR__ . '/fixtures/ok.txt');
        $this->assertTrue($scanner->clean());
    }
}
