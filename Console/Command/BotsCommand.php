<?php
/**
 * Copyright (c) Storetown Media. All rights reserved.
 * See LICENSE for license details.
 */
declare(strict_types=1);

namespace Storetown\ShopGuard\Console\Command;

use Storetown\ShopGuard\Model\BotAnalyzer;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * bin/magento shopguard:bots [--dry-run]
 */
class BotsCommand extends Command
{
    /**
     * @param BotAnalyzer $analyzer
     */
    public function __construct(private BotAnalyzer $analyzer)
    {
        parent::__construct();
    }

    /**
     * @inheritdoc
     */
    protected function configure(): void
    {
        $this->setName('shopguard:bots')
            ->setDescription('Run the bot scan over the collected traffic now')
            ->addOption('dry-run', null, InputOption::VALUE_NONE, 'Show what would be blocked, change nothing');
        parent::configure();
    }

    /**
     * @inheritdoc
     */
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $dry = (bool)$input->getOption('dry-run');
        $s = $this->analyzer->run($dry);
        $output->writeln(sprintf(
            '%s mode=%s, ~%d requests in %.1f h, %d entries expired',
            $dry ? 'Dry run:' : 'Bot scan:',
            $s['mode'],
            $s['requests'],
            $s['hours'],
            $s['expired']
        ));
        foreach ($s['shared'] as $ip) {
            $output->writeln(sprintf('  Not banned, carries over 30%% of all traffic (proxy?): %s', $ip));
        }
        foreach (['ips' => 'IP', 'agents' => 'User agent'] as $key => $label) {
            foreach ($s[$key] as $entry) {
                $output->writeln(sprintf('  %-10s %s  # %s %s', $label, $entry['value'], $entry['until'], $entry['note']));
            }
        }
        return 0;
    }
}
