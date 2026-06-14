<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Import;

/**
 * Turns the rule files of an upstream CRS release into the per-paranoia-level
 * rule files shipped in resources/rules.
 *
 * The importer works on in-memory file contents so the download/extraction
 * step stays separate (and the importer itself is testable without network
 * or a real filesystem source).
 */
final readonly class Importer
{
    private const SOURCE_FILE_PATTERN = '/^REQUEST-\d{3}-.+\.conf$/';

    private const GENERATED_FILE_PATTERN = '/(\.pl[1-4]\.conf|\.data)$/';

    private RuleFileTransformer $ruleFileTransformer;

    public function __construct()
    {
        $this->ruleFileTransformer = new RuleFileTransformer();
    }

    /**
     * @param array<string, string> $sourceFiles Upstream file contents keyed by file name (rule .conf and .data files)
     * @param string $crsVersion Upstream release tag, for example "v4.16.0"
     * @param string $destinationDirectory Directory the generated rule files are written to
     * @param string $importedAt Import timestamp in ISO 8601 form
     * @param string|null $upstreamLicense Upstream LICENSE text, copied next to the generated rules
     * @param string|null $upstreamNotice Upstream NOTICE text (Apache-2.0 attribution), copied when present
     */
    public function import(
        array $sourceFiles,
        string $crsVersion,
        string $destinationDirectory,
        string $importedAt,
        ?string $upstreamLicense = null,
        ?string $upstreamNotice = null,
    ): ImportReport {
        $ruleFilesByName = $this->selectRuleFiles($sourceFiles);
        if ($ruleFilesByName === []) {
            throw new \RuntimeException('No REQUEST-*.conf rule files found in the import source.');
        }

        $this->ensureDirectory($destinationDirectory);
        $this->removeGeneratedFiles($destinationDirectory);

        $ruleCountsByParanoiaLevel = [1 => 0, 2 => 0, 3 => 0, 4 => 0];
        $droppedRuleCounts = [];
        $referencedDataFiles = [];
        $generatedFiles = [];

        foreach ($ruleFilesByName as $fileName => $content) {
            $fileTransformation = $this->ruleFileTransformer->transform($content);

            foreach ($fileTransformation->droppedRuleCounts as $reason => $count) {
                $droppedRuleCounts[$reason] = ($droppedRuleCounts[$reason] ?? 0) + $count;
            }

            foreach ($fileTransformation->referencedDataFiles as $dataFile) {
                $referencedDataFiles[$dataFile] = true;
            }

            foreach ($fileTransformation->ruleLinesByParanoiaLevel as $paranoiaLevel => $ruleLines) {
                $ruleCountsByParanoiaLevel[$paranoiaLevel] += count($ruleLines);
                $generatedFileName = $this->generatedFileName($fileName, $paranoiaLevel);
                $this->writeFile(
                    $destinationDirectory,
                    $generatedFileName,
                    $this->renderRuleFile($fileName, $crsVersion, $paranoiaLevel, $ruleLines),
                );
                $generatedFiles[] = $generatedFileName;
            }
        }

        $dataFiles = [];
        foreach (array_keys($referencedDataFiles) as $dataFile) {
            $content = $this->findDataFile($sourceFiles, $dataFile);
            $this->writeFile($destinationDirectory, $dataFile, $content);
            $generatedFiles[] = $dataFile;
            $dataFiles[] = $dataFile;
        }

        if ($upstreamLicense !== null) {
            $this->writeFile($destinationDirectory, 'LICENSE', $upstreamLicense);
            $generatedFiles[] = 'LICENSE';
        }

        if ($upstreamNotice !== null) {
            $this->writeFile($destinationDirectory, 'NOTICE', $upstreamNotice);
            $generatedFiles[] = 'NOTICE';
        }

        ksort($droppedRuleCounts);
        sort($dataFiles, SORT_STRING);
        sort($generatedFiles, SORT_STRING);

        $importReport = new ImportReport(
            $crsVersion,
            $importedAt,
            $ruleCountsByParanoiaLevel,
            $droppedRuleCounts,
            array_keys($ruleFilesByName),
            $dataFiles,
            $generatedFiles,
        );

        $manifestJson = json_encode($importReport->toManifestArray(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        if ($manifestJson === false) {
            throw new \RuntimeException('Cannot encode the import manifest as JSON.');
        }

        $this->writeFile($destinationDirectory, 'manifest.json', $manifestJson . "\n");

        return $importReport;
    }

    /**
     * Request-phase rule files, excluding exclusion templates, sorted by name.
     *
     * @param array<string, string> $sourceFiles
     * @return array<string, string>
     */
    private function selectRuleFiles(array $sourceFiles): array
    {
        $ruleFiles = [];
        foreach ($sourceFiles as $path => $content) {
            $fileName = basename($path);
            if (preg_match(self::SOURCE_FILE_PATTERN, $fileName) !== 1) {
                continue;
            }

            if (str_contains($fileName, 'EXCLUSION')) {
                continue;
            }

            $ruleFiles[$fileName] = $content;
        }

        ksort($ruleFiles, SORT_STRING);
        return $ruleFiles;
    }

    /**
     * @param array<string, string> $sourceFiles
     */
    private function findDataFile(array $sourceFiles, string $dataFileName): string
    {
        foreach ($sourceFiles as $path => $content) {
            if (basename($path) === $dataFileName) {
                return $content;
            }
        }

        throw new \RuntimeException(sprintf('Data file "%s" is referenced by a kept rule but missing in the import source.', $dataFileName));
    }

    private function generatedFileName(string $sourceFileName, int $paranoiaLevel): string
    {
        return sprintf('%s.pl%d.conf', basename($sourceFileName, '.conf'), $paranoiaLevel);
    }

    /**
     * @param list<string> $ruleLines
     */
    private function renderRuleFile(string $sourceFileName, string $crsVersion, int $paranoiaLevel, array $ruleLines): string
    {
        $header = sprintf(
            "# Generated by flowd/phirewall-preset-owasp-crs. Do not edit.\n"
            . "# Source: %s (OWASP CRS %s), paranoia level %d, %d rules.\n"
            . "# Modified: filtered to engine-supported rules and split per paranoia level; not the complete CRS.\n"
            . "# OWASP CRS is Copyright (c) the OWASP CRS project, licensed under Apache-2.0 (see LICENSE).\n\n",
            $sourceFileName,
            $crsVersion,
            $paranoiaLevel,
            count($ruleLines),
        );

        return $header . implode("\n", $ruleLines) . "\n";
    }

    private function ensureDirectory(string $directory): void
    {
        if (is_dir($directory)) {
            return;
        }

        if (!mkdir($directory, 0o775, true) && !is_dir($directory)) {
            throw new \RuntimeException('Cannot create rules directory: ' . $directory);
        }
    }

    /**
     * Remove files from a previous import so rules dropped upstream do not linger.
     */
    private function removeGeneratedFiles(string $directory): void
    {
        $entries = scandir($directory);
        if ($entries === false) {
            throw new \RuntimeException('Cannot list rules directory: ' . $directory);
        }

        foreach ($entries as $entry) {
            $isGenerated = preg_match(self::GENERATED_FILE_PATTERN, $entry) === 1
                || $entry === 'manifest.json'
                || $entry === 'LICENSE'
                || $entry === 'NOTICE';
            if (!$isGenerated) {
                continue;
            }

            $path = rtrim($directory, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $entry;
            if (is_file($path) && !unlink($path)) {
                throw new \RuntimeException('Cannot remove previously generated file: ' . $path);
            }
        }
    }

    private function writeFile(string $directory, string $fileName, string $content): void
    {
        $path = rtrim($directory, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $fileName;
        if (file_put_contents($path, $content) === false) {
            throw new \RuntimeException('Cannot write generated file: ' . $path);
        }
    }
}
