<?php

declare(strict_types=1);

// Package checkout (own vendor/) or monorepo root (vendor/ above packages/).
require is_file(__DIR__ . '/../vendor/autoload.php')
    ? __DIR__ . '/../vendor/autoload.php'
    : __DIR__ . '/../../../vendor/autoload.php';
