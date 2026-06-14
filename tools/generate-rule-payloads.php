<?php

/**
 * Development helper: derives a triggering payload for every shipped CRS rule
 * and verifies each one fires its rule in isolation through the engine.
 *
 * Writes tests/Fixtures/rule-payloads.php (rule id => [vector, payload]).
 * Not shipped/autoloaded; run manually after an import:
 *   php tools/generate-rule-payloads.php
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRule;
use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRuleSet;
use Flowd\PhirewallPresetOwaspCrs\Engine\SecRuleLoader;
use Flowd\PhirewallPresetOwaspCrs\Import\LogicalLineSplitter;
use Nyholm\Psr7\ServerRequest;

mt_srand(1337); // deterministic output across runs

/** ------------------------------------------------------------------ Regex AST sampler */

final class RegexSampler
{
    private string $pattern;
    private int $position = 0;
    private int $length;

    /** @var array<string, list<string>> */
    private array $dataPhrases;

    /**
     * @param array<string, list<string>> $dataPhrases
     */
    public function __construct(array $dataPhrases)
    {
        $this->dataPhrases = $dataPhrases;
        $this->pattern = '';
        $this->length = 0;
    }

    /**
     * Produce a string that matches $regex (PCRE body, no delimiters), or null.
     */
    public function sample(string $regex): ?string
    {
        // (?i) and inline flags are handled by matching case-insensitively at verify time.
        $regex = preg_replace('/^\(\?[a-z]+\)/', '', $regex) ?? $regex;
        $this->pattern = $regex;
        $this->length = strlen($regex);

        $delimited = '#' . str_replace('#', '\#', $regex) . '#is';
        if (@preg_match($delimited, '') === false) {
            return null; // pattern we cannot even compile
        }

        for ($attempt = 0; $attempt < 4000; ++$attempt) {
            $this->position = 0;
            $node = $this->parseAlternation();
            $candidate = $this->emit($node);
            if ($candidate === null) {
                continue;
            }

            if (@preg_match($delimited, $candidate) === 1) {
                return $candidate;
            }
        }

        return null;
    }

    /** @return array<mixed> */
    private function parseAlternation(): array
    {
        $branches = [$this->parseSequence()];
        while ($this->peek() === '|') {
            ++$this->position;
            $branches[] = $this->parseSequence();
        }

        return ['type' => 'alt', 'branches' => $branches];
    }

    /** @return array<mixed> */
    private function parseSequence(): array
    {
        $items = [];
        while ($this->position < $this->length) {
            $char = $this->peek();
            if ($char === '|' || $char === ')') {
                break;
            }

            $atom = $this->parseAtom();
            if ($atom === null) {
                break;
            }

            $atom = $this->parseQuantifier($atom);
            $items[] = $atom;
        }

        return ['type' => 'seq', 'items' => $items];
    }

    /** @return array<mixed>|null */
    private function parseAtom(): ?array
    {
        $char = $this->pattern[$this->position];

        if ($char === '(') {
            ++$this->position;
            // group flags / lookarounds
            $lookaround = false;
            if ($this->peek() === '?') {
                ++$this->position;
                $next = $this->peek();
                if ($next === ':') {
                    ++$this->position;
                } elseif ($next === '=' || $next === '!') {
                    ++$this->position;
                    $lookaround = true;
                } elseif ($next === '<') {
                    ++$this->position;
                    $after = $this->peek();
                    if ($after === '=' || $after === '!') {
                        ++$this->position;
                        $lookaround = true;
                    } else {
                        // named group (?<name>...)
                        while ($this->position < $this->length && $this->peek() !== '>') {
                            ++$this->position;
                        }
                        if ($this->peek() === '>') {
                            ++$this->position;
                        }
                    }
                } else {
                    // inline flags (?i) etc up to ) or :
                    while ($this->position < $this->length && $this->peek() !== ')' && $this->peek() !== ':') {
                        ++$this->position;
                    }
                    if ($this->peek() === ':') {
                        ++$this->position;
                    }
                }
            }

            $inner = $this->parseAlternation();
            if ($this->peek() === ')') {
                ++$this->position;
            }

            if ($lookaround) {
                return ['type' => 'empty'];
            }

            return $inner;
        }

        if ($char === '[') {
            return $this->parseCharClass();
        }

        if ($char === '\\') {
            return $this->parseEscape();
        }

        if ($char === '.') {
            ++$this->position;
            return ['type' => 'any'];
        }

        if ($char === '^' || $char === '$') {
            ++$this->position;
            return ['type' => 'empty'];
        }

        ++$this->position;
        return ['type' => 'lit', 'value' => $char];
    }

    /** @return array<mixed> */
    private function parseEscape(): array
    {
        ++$this->position; // consume backslash
        $char = $this->pattern[$this->position] ?? '';
        ++$this->position;

        $classes = [
            'd' => ['0', '9'],
            'w' => ['a', 'z'],
            's' => [' ', ' '],
        ];

        switch ($char) {
            case 'd':
                return ['type' => 'class', 'chars' => str_split('0123456789')];
            case 'w':
                return ['type' => 'class', 'chars' => str_split('abcdefghijklmnopqrstuvwxyz0123456789_')];
            case 's':
                return ['type' => 'lit', 'value' => ' '];
            case 'b':
            case 'B':
            case 'A':
            case 'Z':
            case 'z':
            case 'G':
                return ['type' => 'empty'];
            case 'n':
                return ['type' => 'lit', 'value' => "\n"];
            case 'r':
                return ['type' => 'lit', 'value' => "\r"];
            case 't':
                return ['type' => 'lit', 'value' => "\t"];
            case 'x':
                $hex = substr($this->pattern, $this->position, 2);
                if (preg_match('/^[0-9A-Fa-f]{2}$/', $hex) === 1) {
                    $this->position += 2;
                    return ['type' => 'lit', 'value' => chr((int)hexdec($hex))];
                }
                if ($this->peek() === '{') {
                    $end = strpos($this->pattern, '}', $this->position);
                    if ($end !== false) {
                        $hex = substr($this->pattern, $this->position + 1, $end - $this->position - 1);
                        $this->position = $end + 1;
                        return ['type' => 'lit', 'value' => chr((int)hexdec($hex) & 0xFF)];
                    }
                }
                return ['type' => 'lit', 'value' => 'x'];
            default:
                if (preg_match('/[1-9]/', $char) === 1) {
                    return ['type' => 'empty']; // backreference
                }
                return ['type' => 'lit', 'value' => $char];
        }
    }

    /** @return array<mixed> */
    private function parseCharClass(): array
    {
        ++$this->position; // consume [
        $negated = false;
        if ($this->peek() === '^') {
            $negated = true;
            ++$this->position;
        }

        $chars = [];
        $first = true;
        while ($this->position < $this->length) {
            $char = $this->pattern[$this->position];
            if ($char === ']' && !$first) {
                ++$this->position;
                break;
            }

            $first = false;

            if ($char === '\\') {
                $escape = $this->parseEscape();
                if ($escape['type'] === 'class') {
                    $chars = array_merge($chars, $escape['chars']);
                } elseif ($escape['type'] === 'lit') {
                    $chars[] = $escape['value'];
                }
                continue;
            }

            // range a-z
            if ($this->position + 2 < $this->length
                && $this->pattern[$this->position + 1] === '-'
                && $this->pattern[$this->position + 2] !== ']') {
                $from = ord($char);
                $to = ord($this->pattern[$this->position + 2]);
                for ($code = $from; $code <= $to && $code - $from < 64; ++$code) {
                    $chars[] = chr($code);
                }
                $this->position += 3;
                continue;
            }

            $chars[] = $char;
            ++$this->position;
        }

        if ($negated) {
            $allowed = [];
            $blocked = array_flip($chars);
            foreach (str_split('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ./()-_=') as $candidate) {
                if (!isset($blocked[$candidate])) {
                    $allowed[] = $candidate;
                }
            }

            $chars = $allowed !== [] ? $allowed : ['x'];
        }

        if ($chars === []) {
            $chars = ['x'];
        }

        return ['type' => 'class', 'chars' => array_values($chars)];
    }

    /**
     * @param array<mixed> $atom
     * @return array<mixed>
     */
    private function parseQuantifier(array $atom): array
    {
        $char = $this->peek();
        $min = 1;
        $max = 1;

        if ($char === '*') {
            ++$this->position;
            $min = 0;
            $max = 3;
        } elseif ($char === '+') {
            ++$this->position;
            $min = 1;
            $max = 3;
        } elseif ($char === '?') {
            ++$this->position;
            $min = 0;
            $max = 1;
        } elseif ($char === '{') {
            $end = strpos($this->pattern, '}', $this->position);
            if ($end !== false) {
                $spec = substr($this->pattern, $this->position + 1, $end - $this->position - 1);
                $this->position = $end + 1;
                if (str_contains($spec, ',')) {
                    [$lo, $hi] = explode(',', $spec, 2);
                    $min = $lo === '' ? 0 : (int)$lo;
                    $max = $hi === '' ? $min + 2 : (int)$hi;
                } else {
                    $min = $max = (int)$spec;
                }
            }
        } else {
            return $atom;
        }

        // consume lazy/possessive markers
        if ($this->peek() === '?' || $this->peek() === '+') {
            ++$this->position;
        }

        return ['type' => 'rep', 'child' => $atom, 'min' => $min, 'max' => max($min, $max)];
    }

    private function peek(): string
    {
        return $this->pattern[$this->position] ?? '';
    }

    /**
     * @param array<mixed> $node
     */
    private function emit(array $node): ?string
    {
        switch ($node['type']) {
            case 'empty':
                return '';
            case 'lit':
                return $node['value'];
            case 'any':
                return 'a';
            case 'class':
                $chars = $node['chars'];
                return $chars[mt_rand(0, count($chars) - 1)];
            case 'seq':
                $out = '';
                foreach ($node['items'] as $item) {
                    $part = $this->emit($item);
                    if ($part === null) {
                        return null;
                    }
                    $out .= $part;
                }
                return $out;
            case 'alt':
                $branches = $node['branches'];
                return $this->emit($branches[mt_rand(0, count($branches) - 1)]);
            case 'rep':
                $count = mt_rand($node['min'], $node['max']);
                $out = '';
                for ($index = 0; $index < $count; ++$index) {
                    $part = $this->emit($node['child']);
                    if ($part === null) {
                        return null;
                    }
                    $out .= $part;
                }
                return $out;
            default:
                return null;
        }
    }
}

/** ------------------------------------------------------------------ Load data-file phrases */

$rulesDir = __DIR__ . '/../resources/rules';
$dataPhrases = [];
foreach (glob($rulesDir . '/*.data') ?: [] as $dataFile) {
    $lines = [];
    foreach (file($dataFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $line) {
        $line = trim($line);
        if ($line !== '' && !str_starts_with($line, '#')) {
            $lines[] = $line;
        }
    }
    $dataPhrases[basename($dataFile)] = $lines;
}

/** ------------------------------------------------------------------ Injection vectors */

/**
 * Build a request that places $payload into the variable the rule inspects.
 *
 * @return array{0: string, 1: \Psr\Http\Message\ServerRequestInterface}
 */
function requestFor(string $vector, string $payload): array
{
    $base = new ServerRequest('GET', 'https://example.test/');
    switch ($vector) {
        case 'args':
            return [$vector, $base->withQueryParams(['p' => $payload])];
        case 'args_names':
            return [$vector, $base->withQueryParams([$payload => '1'])];
        case 'body':
            return [$vector, (new ServerRequest('POST', 'https://example.test/'))->withParsedBody(['p' => $payload])];
        case 'query_string':
            return [$vector, new ServerRequest('GET', 'https://example.test/?' . $payload)];
        case 'uri':
            return [$vector, new ServerRequest('GET', 'https://example.test/' . ltrim($payload, '/'))];
        case 'filename':
            return [$vector, new ServerRequest('GET', 'https://example.test/' . ltrim(str_replace('?', '', $payload), '/'))];
        case 'cookie':
            return [$vector, $base->withCookieParams(['c' => $payload])];
        case 'header_referer':
            return [$vector, $base->withHeader('Referer', $payload)];
        case 'header_ua':
            return [$vector, $base->withHeader('User-Agent', $payload)];
        case 'method':
            return [$vector, (new ServerRequest($payload !== '' ? $payload : 'GET', 'https://example.test/'))];
        default:
            return [$vector, $base];
    }
}

/** @return list<string> */
function vectorsFor(CoreRule $rule): array
{
    $variables = array_map('strtoupper', $rule->variables);
    $has = static fn(string $name): bool => in_array($name, $variables, true)
        || (bool)array_filter($variables, static fn(string $variable): bool => str_starts_with($variable, $name . ':'));

    $vectors = [];
    if ($has('ARGS')) {
        $vectors[] = 'args';
        $vectors[] = 'body';
    }
    if ($has('ARGS_NAMES')) {
        $vectors[] = 'args_names';
    }
    if ($has('QUERY_STRING')) {
        $vectors[] = 'query_string';
    }
    if ($has('REQUEST_URI')) {
        $vectors[] = 'uri';
        $vectors[] = 'query_string';
    }
    if ($has('REQUEST_FILENAME')) {
        $vectors[] = 'filename';
    }
    if ($has('REQUEST_COOKIES')) {
        $vectors[] = 'cookie';
    }
    if ($has('REQUEST_HEADERS')) {
        $vectors[] = 'header_referer';
        $vectors[] = 'header_ua';
    }
    if ($has('REQUEST_METHOD')) {
        $vectors[] = 'method';
    }

    // fallback: try the broad ones
    $vectors[] = 'args';
    $vectors[] = 'uri';

    return array_values(array_unique($vectors));
}

/** ------------------------------------------------------------------ Candidate payloads per rule */

/** @return list<string> */
function candidatePayloads(CoreRule $rule, RegexSampler $sampler, array $dataPhrases): array
{
    $operator = strtolower($rule->operator);
    $argument = $rule->operatorArgument;

    if ($operator === '@pmfromfile') {
        $file = basename($argument);
        $phrases = $dataPhrases[$file] ?? [];
        return array_slice($phrases, 0, 6);
    }

    if ($operator === '@pm') {
        $phrases = preg_split('/\s+/', trim($argument)) ?: [];
        return array_slice($phrases, 0, 6);
    }

    if ($operator === '@contains') {
        return [$argument];
    }

    if ($operator === '@rx') {
        $samples = [];
        for ($try = 0; $try < 6; ++$try) {
            $sample = $sampler->sample($argument);
            if ($sample !== null && $sample !== '') {
                $samples[$sample] = true;
            }
        }
        return array_keys($samples);
    }

    return [];
}

/** ------------------------------------------------------------------ Manual overrides */

/**
 * Payloads the random sampler cannot derive (anomaly counters, binary signatures,
 * data-file basenames). Each is still verified against the engine below.
 *
 * @var array<int, array{vector: string, payload: string}>
 */
$manualOverrides = [
    942460 => ['vector' => 'args', 'payload' => '!!!!'],
    942430 => ['vector' => 'args', 'payload' => str_repeat('<', 12)],
    942431 => ['vector' => 'args', 'payload' => str_repeat('<', 6)],
    942432 => ['vector' => 'args', 'payload' => str_repeat('<', 2)],
    942420 => ['vector' => 'cookie', 'payload' => str_repeat('<', 8)],
    942421 => ['vector' => 'cookie', 'payload' => str_repeat('<', 3)],
    944250 => ['vector' => 'args', 'payload' => 'java runtime'],
    930140 => ['vector' => 'filename', 'payload' => '.qwen_code'],
    // Java serialized-object header: the engine compiles @rx with the /u flag, so the
    // signature bytes must be supplied as their UTF-8 code points (U+00AC U+00ED ...).
    944200 => ['vector' => 'args', 'payload' => "\u{00AC}\u{00ED}\u{0000}\u{0005}"],
];

/**
 * Rules that cannot be triggered through a normalized PSR-7 request and the
 * engine's supported variable collectors. Recorded so the test can assert they
 * are still present and parseable without claiming a behavioral block.
 *
 * @var array<int, string>
 */
$documentedUnreachable = [
    920260 => 'REQUEST_URI percent-encoding rewrites the literal "%uff"; REQUEST_BODY has no collector.',
    921190 => 'A newline cannot survive in a PSR-7 path basename (REQUEST_FILENAME).',
    931131 => 'A "scheme://host" string cannot appear in a basename (REQUEST_FILENAME).',
];

/** ------------------------------------------------------------------ Derive + verify */

$fixtures = [];
$failures = [];
$ruleFiles = glob($rulesDir . '/REQUEST-*.conf') ?: [];
sort($ruleFiles);

foreach ($ruleFiles as $ruleFile) {
    $ruleSet = SecRuleLoader::fromFile($ruleFile);
    foreach ($ruleSet->ids() as $id) {
        $rule = $ruleSet->getRule($id);
        if (!$rule instanceof CoreRule) {
            continue;
        }

        if (isset($documentedUnreachable[$id])) {
            continue;
        }

        // Isolate the rule so a match can only be attributed to it.
        $isolated = new CoreRuleSet([$rule]);

        $matched = null;
        $candidates = [];
        if (isset($manualOverrides[$id])) {
            $candidates[] = [$manualOverrides[$id]['vector'], $manualOverrides[$id]['payload']];
        } else {
            $sampler = new RegexSampler($dataPhrases);
            foreach (candidatePayloads($rule, $sampler, $dataPhrases) as $payload) {
                foreach (vectorsFor($rule) as $vector) {
                    $candidates[] = [$vector, $payload];
                }
            }
        }

        foreach ($candidates as [$vector, $payload]) {
            try {
                [$usedVector, $request] = requestFor($vector, $payload);
            } catch (\InvalidArgumentException) {
                continue; // payload not placeable in this vector (e.g. control chars in a header)
            }

            if ($isolated->match($request) === $id) {
                $matched = ['vector' => $usedVector, 'payload' => $payload];
                break;
            }
        }

        if ($matched === null) {
            $failures[] = sprintf('%d (%s %s)', $id, $rule->operator, basename($ruleFile));
            continue;
        }

        $fixtures[$id] = $matched;
    }
}

ksort($fixtures);
ksort($documentedUnreachable);

/** ------------------------------------------------------------------ Emit fixtures file */

$export = "<?php\n\ndeclare(strict_types=1);\n\n"
    . "/**\n"
    . " * Triggering payloads for the shipped CRS rules, generated and verified by\n"
    . " * tools/generate-rule-payloads.php. Each entry fires its rule id in isolation\n"
    . " * through the Phirewall SecRule engine.\n"
    . " *\n"
    . " * Payloads are base64-encoded because many contain control or non-UTF-8 bytes\n"
    . " * that must not sit raw in PHP source. 'unreachable' lists rules that cannot be\n"
    . " * triggered through a normalized PSR-7 request, with the reason.\n"
    . " *\n"
    . " * Do not edit by hand; regenerate after an import.\n"
    . " *\n"
    . " * @return array{\n"
    . " *     crsVersion: string,\n"
    . " *     payloads: array<int, array{vector: string, payload_base64: string}>,\n"
    . " *     unreachable: array<int, string>,\n"
    . " * }\n"
    . " */\n\n"
    . "return [\n"
    . sprintf("    'crsVersion' => %s,\n", var_export(\Flowd\PhirewallPresetOwaspCrs\Manifest::read($rulesDir)->crsVersion, true))
    . "    'payloads' => [\n";

foreach ($fixtures as $id => $entry) {
    $export .= sprintf(
        "        %d => ['vector' => %s, 'payload_base64' => %s],\n",
        $id,
        var_export($entry['vector'], true),
        var_export(base64_encode($entry['payload']), true),
    );
}

$export .= "    ],\n    'unreachable' => [\n";
foreach ($documentedUnreachable as $id => $reason) {
    $export .= sprintf("        %d => %s,\n", $id, var_export($reason, true));
}

$export .= "    ],\n];\n";

$fixturePath = __DIR__ . '/../tests/Fixtures/rule-payloads.php';
@mkdir(dirname($fixturePath), 0o775, true);
file_put_contents($fixturePath, $export);

printf(
    "Covered %d rules behaviorally, %d documented-unreachable, %d without a verified payload.\n",
    count($fixtures),
    count($documentedUnreachable),
    count($failures),
);
if ($failures !== []) {
    echo "Uncovered:\n  " . implode("\n  ", $failures) . "\n";
}
