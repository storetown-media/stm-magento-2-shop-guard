<?php
/**
 * Copyright (c) Storetown Media. All rights reserved.
 * See LICENSE for license details.
 */
declare(strict_types=1);

namespace Storetown\ShopGuard\Console\Command;

use Storetown\ShopGuard\Model\CardBrake;
use Storetown\ShopGuard\Model\Config;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Addresses that went over the payment attempt limit, so the limit can be judged before the brake blocks
 */
class CardTestsCommand extends Command
{
    /**
     * @param CardBrake $cardBrake
     * @param Config $config
     */
    public function __construct(
        private CardBrake $cardBrake,
        private Config $config
    ) {
        parent::__construct();
    }

    /**
     * @inheritdoc
     */
    protected function configure(): void
    {
        $this->setName('shopguard:cardtests')
            ->setDescription('List addresses with more payment attempts per hour than the limit, last 7 days');
        parent::configure();
    }

    /**
     * @inheritdoc
     */
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $output->writeln(sprintf(
            '<info>Card test brake</info>: mode %s, limit %d payment attempts per address and hour',
            $this->config->value(Config::CARD_MODE) ?: Config::MODE_REPORT,
            $this->config->int(Config::CARD_LIMIT, 8)
        ));
        $observed = $this->cardBrake->observed();
        if (!$observed) {
            $output->writeln('No address went over the limit in the last 7 days.');
            return 0;
        }
        $output->writeln(sprintf('%-40s %-8s %5s %5s  %-16s %s', 'Address', 'Mode', 'Over', 'Max', 'First', 'Last'));
        foreach ($observed as $ip => $o) {
            $output->writeln(sprintf(
                '%-40s %-8s %5d %5d  %-16s %s',
                $ip,
                $o['mode'],
                $o['count'],
                $o['max'],
                substr($o['first'], 0, 16),
                substr($o['last'], 0, 16)
            ));
        }
        return 0;
    }
}
