<?php

declare(strict_types=1);

use ShipMonk\ComposerDependencyAnalyser\Config\Configuration;
use ShipMonk\ComposerDependencyAnalyser\Config\ErrorType;

// Baseline of the findings that existed when the monorepo was set up. New undeclared
// dependencies still fail the check. Declare an entry in composer.json and remove it
// here once it is fixed.
return (new Configuration())
    ->ignoreErrorsOnExtension('ext-ctype', [ErrorType::SHADOW_DEPENDENCY])
    ->ignoreErrorsOnPackage('psr/http-message', [ErrorType::SHADOW_DEPENDENCY])
    ;
