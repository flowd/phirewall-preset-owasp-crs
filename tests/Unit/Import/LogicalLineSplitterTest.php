<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Tests\Unit\Import;

use Flowd\PhirewallPresetOwaspCrs\Import\LogicalLineSplitter;
use PHPUnit\Framework\TestCase;

final class LogicalLineSplitterTest extends TestCase
{
    public function testJoinsBackslashContinuationsWithASingleSpace(): void
    {
        $text = "SecRule ARGS \\\n    \"@rx select\" \\\n    \"id:1,deny\"\n";

        $this->assertSame(['SecRule ARGS "@rx select" "id:1,deny"'], (new LogicalLineSplitter())->split($text));
    }

    public function testSkipsCommentAndBlankLines(): void
    {
        $text = "# a comment\n\nSecRule ARGS \"@rx a\" \"id:1,deny\"\n   # indented comment\n";

        $this->assertSame(['SecRule ARGS "@rx a" "id:1,deny"'], (new LogicalLineSplitter())->split($text));
    }

    public function testKeepsEscapedQuotesAndBackslashesInsideQuotedSegments(): void
    {
        $text = 'SecRule ARGS "@rx a\\"b\\\\" "id:7,deny"' . "\n";

        $this->assertSame(['SecRule ARGS "@rx a\\"b\\\\" "id:7,deny"'], (new LogicalLineSplitter())->split($text));
    }

    public function testHashInsideAQuotedSegmentIsNotAComment(): void
    {
        $text = "SecRule ARGS \"@rx a#b\" \"id:9,deny\"\n";

        $this->assertSame(['SecRule ARGS "@rx a#b" "id:9,deny"'], (new LogicalLineSplitter())->split($text));
    }

    public function testFinalLineWithoutTrailingNewlineIsKept(): void
    {
        $this->assertSame(['SecRule ARGS "@rx a" "id:1,deny"'], (new LogicalLineSplitter())->split('SecRule ARGS "@rx a" "id:1,deny"'));
    }

    public function testSplitsMultipleDirectives(): void
    {
        $text = "SecMarker BEGIN\nSecRule ARGS \"@rx a\" \"id:1,deny\"\nSecRule ARGS \"@rx b\" \"id:2,deny\"\n";

        $this->assertSame([
            'SecMarker BEGIN',
            'SecRule ARGS "@rx a" "id:1,deny"',
            'SecRule ARGS "@rx b" "id:2,deny"',
        ], (new LogicalLineSplitter())->split($text));
    }
}
