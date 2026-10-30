<?php
/**
 * Copyright (c) Storetown Media. All rights reserved.
 * See LICENSE for license details.
 */
declare(strict_types=1);

namespace Storetown\ShopGuard\Console\Command;

use Storetown\ShopGuard\Model\RuleFeed;
use Storetown\ShopGuard\Model\WarningCheck;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * State of the attack patterns from Storetown Media; fetch now, import a signed file, or check a file before signing
 */
class RulesCommand extends Command
{
    /**
     * @param RuleFeed $ruleFeed
     * @param WarningCheck $warningCheck
     */
    public function __construct(
        private RuleFeed $ruleFeed,
        private WarningCheck $warningCheck
    ) {
        parent::__construct();
    }

    /**
     * @inheritdoc
     */
    protected function configure(): void
    {
        $this->setName('shopguard:rules')
            ->setDescription('Show the attack patterns loaded from Storetown Media, or fetch them now')
            ->addOption('update', null, InputOption::VALUE_NONE, 'Fetch the signed feed from storetown-media.de now')
            ->addOption(
                'file',
                null,
                InputOption::VALUE_REQUIRED,
                'Import a signed feed file instead, its signature next to it as <file>.sig'
            )
            ->addOption(
                'check',
                null,
                InputOption::VALUE_REQUIRED,
                'Check an unsigned feed file before it is signed: format, patterns, ordinary requests'
            );
        parent::configure();
    }

    /**
     * @inheritdoc
     */
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        if ($check = (string)$input->getOption('check')) {
            return $this->check($check, $output);
        }
        if ($file = (string)$input->getOption('file')) {
            $json = is_file($file) ? (string)file_get_contents($file) : '';
            $sig = is_file($file . '.sig') ? (string)file_get_contents($file . '.sig') : '';
            $result = $this->ruleFeed->import($json, $sig);
            $output->writeln(sprintf('<%1$s>%2$s</%1$s>', $result['status'] === 'error' ? 'error' : 'info', $result['message']));
        } elseif ($input->getOption('update')) {
            $result = $this->ruleFeed->update();
            $output->writeln(sprintf('<%1$s>%2$s</%1$s>', $result['status'] === 'error' ? 'error' : 'info', $result['message']));
        }

        $state = $this->ruleFeed->state();
        if (!$state) {
            $output->writeln('No feed loaded yet. The cron job fetches it every hour; now: bin/magento shopguard:rules --update');
            return 0;
        }
        $output->writeln(sprintf(
            '<info>Feed %d</info> of %s, signed with %s, last checked %s',
            (int)($state['serial'] ?? 0),
            (string)($state['issued'] ?? '?'),
            (string)($state['key'] ?? '?'),
            date('Y-m-d H:i', (int)($state['checked'] ?? 0))
        ));
        if (!empty($state['error'])) {
            $output->writeln(sprintf('<error>Last check failed: %s</error>', $state['error']));
        }
        $hits = $this->ruleFeed->hits();
        foreach ($this->ruleFeed->rules() as $rule) {
            $output->writeln(sprintf(
                '  %-5s %-22s %s%s',
                $rule['action'],
                $rule['id'],
                $rule['title'],
                isset($hits[$rule['id']]) ? sprintf(' (%d hits in 30 days)', $hits[$rule['id']]) : ''
            ));
        }
        foreach ($this->warningCheck->all() as $warning) {
            $output->writeln(sprintf(
                '  warning %-8s %-22s %s – %s',
                $warning['severity'],
                $warning['id'],
                $warning['title']['en'],
                $warning['reasons'] === null ? 'does not affect this shop' : 'AFFECTS this shop: ' . implode(', ', $warning['reasons'])
            ));
        }
        foreach ((array)($state['refused'] ?? []) as $id => $reason) {
            $output->writeln(sprintf('  <comment>refused %s: %s</comment>', $id, $reason));
        }
        return empty($state['error']) ? 0 : 1;
    }

    /**
     * @param string $file
     * @param OutputInterface $output
     * @return int
     */
    private function check(string $file, OutputInterface $output): int
    {
        try {
            $report = $this->ruleFeed->check(is_file($file) ? (string)file_get_contents($file) : '');
        } catch (\RuntimeException $e) {
            $output->writeln('<error>' . $e->getMessage() . '</error>');
            return 1;
        }
        $output->writeln(sprintf('<info>Feed %d</info>: %d rules accepted', $report['serial'], count($report['rules'])));
        foreach ($report['rules'] as $rule) {
            $output->writeln(sprintf('  ok    %-5s %-22s %s', $rule['action'], $rule['id'], $rule['title']));
        }
        foreach ($report['warnings'] as $warning) {
            $output->writeln(sprintf('  ok    warning %-8s %-22s %s', $warning['severity'], $warning['id'], $warning['title']['en']));
        }
        foreach ($report['refused'] as $id => $reason) {
            $output->writeln(sprintf('  <error>REFUSED %s: %s</error>', $id, $reason));
        }
        return $report['refused'] ? 1 : 0;
    }
}
