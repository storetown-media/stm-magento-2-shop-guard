<?php
/**
 * Copyright (c) Storetown Media. All rights reserved.
 * See LICENSE for license details.
 */
declare(strict_types=1);

namespace Storetown\ShopGuard\Console\Command;

use Storetown\ShopGuard\Model\FileScanner;
use Storetown\ShopGuard\Model\Integrity;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Integrity check from the command line: compare, or take the current code as the new reference after a deployment
 */
class IntegrityCommand extends Command
{
    /**
     * @param Integrity $integrity
     * @param FileScanner $scanner
     */
    public function __construct(
        private Integrity $integrity,
        private FileScanner $scanner
    ) {
        parent::__construct();
    }

    /**
     * @inheritdoc
     */
    protected function configure(): void
    {
        $this->setName('shopguard:integrity')
            ->setDescription(
                'Compare code files with the reference state, or accept the current state after a deployment'
            )
            ->addOption(
                'accept',
                null,
                InputOption::VALUE_NONE,
                'Take all code files as they are now as the new reference'
            )
            ->addOption(
                'full',
                null,
                InputOption::VALUE_NONE,
                'Hash every file, not only those whose size or times changed'
            );
        parent::configure();
    }

    /**
     * @inheritdoc
     */
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $start = microtime(true);
        if ($input->getOption('accept')) {
            $result = $this->integrity->create('cli');
            $output->writeln(sprintf(
                '<info>New reference state</info>: %d code files, %.1f s',
                $result['files'],
                microtime(true) - $start
            ));
            foreach ($result['suspicious'] as $path => $rule) {
                $output->writeln(sprintf('  CRITICAL %s [%s]', $path, $rule));
            }
            // Refresh the stored findings, so admin and mail show the new state
            $this->scanner->scan();
            return $result['suspicious'] ? 1 : 0;
        }

        $findings = $this->integrity->check((bool)$input->getOption('full'));
        $state = $this->integrity->state();
        $output->writeln(sprintf(
            '<info>Integrity</info>: %d code files in the reference state of %s (%s), %.1f s',
            (int)($state['files'] ?? 0),
            date('Y-m-d H:i', (int)($state['accepted'] ?? 0)),
            (string)($state['accepted_by'] ?? '?'),
            microtime(true) - $start
        ));
        foreach ($findings as $finding) {
            $output->writeln(
                sprintf('  %-8s %-22s %s', strtoupper($finding['level']), $finding['check'], $finding['path'])
            );
        }
        if ($findings) {
            $output->writeln(
                '<comment>After a deployment or update: bin/magento shopguard:integrity --accept</comment>'
            );
        }
        return $findings ? 1 : 0;
    }
}
