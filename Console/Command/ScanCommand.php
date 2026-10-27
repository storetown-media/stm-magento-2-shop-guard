<?php
/**
 * Copyright (c) Storetown Media. All rights reserved.
 * See LICENSE for license details.
 */
declare(strict_types=1);

namespace Storetown\ShopGuard\Console\Command;

use Magento\Framework\App\Area;
use Magento\Framework\App\State;
use Storetown\ShopGuard\Model\FileScanner;
use Storetown\ShopGuard\Model\Notifier;
use Storetown\ShopGuard\Model\SystemCheck;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * bin/magento shopguard:scan [--full] [--notify]
 */
class ScanCommand extends Command
{
    /**
     * @param FileScanner $scanner
     * @param SystemCheck $systemCheck
     * @param Notifier $notifier
     * @param State $state
     */
    public function __construct(
        private FileScanner $scanner,
        private SystemCheck $systemCheck,
        private Notifier $notifier,
        private State $state
    ) {
        parent::__construct();
    }

    /**
     * @inheritdoc
     */
    protected function configure(): void
    {
        $this->setName('shopguard:scan')
            ->setDescription('Scan for backdoors and check PHP and Magento security settings')
            ->addOption('full', null, InputOption::VALUE_NONE, 'Check file contents of all files, not only changed ones')
            ->addOption('notify', null, InputOption::VALUE_NONE, 'Send the mail even if the findings did not change');
        parent::configure();
    }

    /**
     * @inheritdoc
     */
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        try {
            $this->state->setAreaCode(Area::AREA_ADMINHTML);
        } catch (\Throwable $e) {
            unset($e);
        }

        $output->writeln('<info>System check</info> (PHP values from the last web request, CLI as fallback)');
        foreach ($this->systemCheck->run() as $row) {
            $output->writeln(sprintf('  %-8s %s: %s', strtoupper($row['level']), $row['label'], $row['value']));
            if ((string)$row['hint'] !== '') {
                $output->writeln('           ' . $row['hint']);
            }
        }

        $start = microtime(true);
        $findings = $this->scanner->scan((bool)$input->getOption('full'));
        $output->writeln('');
        $output->writeln(sprintf('<info>File scan</info> %.1f s, %d findings', microtime(true) - $start, count($findings)));
        $byCheck = [];
        foreach ($findings as $finding) {
            $byCheck[$finding['check']][] = $finding;
        }
        foreach ($byCheck as $group) {
            $output->writeln(sprintf('  %-8s %s', strtoupper($group[0]['level']), $group[0]['text']));
            foreach ($group as $finding) {
                $output->writeln('           ' . $finding['path']);
            }
            $output->writeln('           <comment>' . __('What to do:') . ' ' . $group[0]['advice'] . '</comment>');
        }

        if ($input->getOption('notify')) {
            $sent = $this->notifier->notify($findings, $this->systemCheck->run(), true);
            $output->writeln($sent ? 'Mail sent.' : 'No mail sent (nothing to report or no recipient).');
        }
        return $findings ? 1 : 0;
    }
}
