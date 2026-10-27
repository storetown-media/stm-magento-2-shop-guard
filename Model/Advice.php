<?php
/**
 * Copyright (c) Storetown Media. All rights reserved.
 * See LICENSE for license details.
 */
declare(strict_types=1);

namespace Storetown\ShopGuard\Model;

use Magento\Framework\Phrase;

/**
 * What a finding means and what the shop owner should do about it. One place for mail, inbox, admin and CLI.
 */
class Advice
{
    /**
     * Area of the shop each check belongs to
     */
    public const AREAS = [
        'uploads' => ['php-in-public', 'session-file', 'foreign-ini', 'htaccess-php', 'php-in-image'],
        'pub' => ['pub-root', 'pub-root-changed', 'index-php'],
        'reports' => ['report-payload'],
        'logs' => ['log-payload'],
        'processes' => ['process-kthread', 'process-tmp', 'process-malware', 'process-fccache'],
        'crontab' => ['crontab'],
        'content' => ['content'],
        'admins' => ['admin-user'],
    ];

    /**
     * @param string $area
     * @return Phrase
     */
    public static function area(string $area): Phrase
    {
        $labels = [
            'uploads' => __('Upload directories (pub/media, pub/static)'),
            'pub' => __('Web root pub/'),
            'reports' => __('Error reports (var/report)'),
            'logs' => __('Log files'),
            'processes' => __('Running processes'),
            'crontab' => __('Crontab'),
            'content' => __('CMS content and configuration'),
            'admins' => __('Admin users'),
        ];
        return $labels[$area] ?? __($area);
    }

    /**
     * @param string $check
     * @return Phrase
     */
    public static function title(string $check): Phrase
    {
        $titles = [
            'php-in-public' => __('PHP file in a public upload directory'),
            'session-file' => __('Session file in pub/media (CosmicSting/SessionReaper)'),
            'foreign-ini' => __('Unknown PHP configuration file'),
            'htaccess-php' => __('.htaccess enables PHP execution'),
            'php-in-image' => __('PHP code disguised as an image'),
            'pub-root' => __('Unknown PHP file in pub/'),
            'pub-root-changed' => __('Allowed file in pub/ was changed'),
            'index-php' => __('pub/index.php contains obfuscated code'),
            'report-payload' => __('Attack code in an error report (StyleSmuggler)'),
            'log-payload' => __('Attack code in a log file (check if it was executed)'),
            'process-kthread' => __('Process disguised as a kernel thread'),
            'process-tmp' => __('Process started from a temporary or deleted file'),
            'process-malware' => __('Known malware process'),
            'process-fccache' => __('fc-cache running as shop user (StyleSmuggler disguise)'),
            'crontab' => __('Suspicious crontab entry'),
            'content' => __('Obfuscated script or template injection in stored content'),
            'admin-user' => __('New admin user, please confirm'),
        ];
        return $titles[$check] ?? __($check);
    }

    /**
     * @param string $check
     * @return Phrase
     */
    public static function advice(string $check): Phrase
    {
        $process = __(
            'A backdoor is running. Note PID and command line, stop it, find out how it starts again '
            . '(crontab, .bashrc, systemd), then change all passwords and the encryption key and inform your hoster.'
        );
        $advice = [
            'php-in-public' => __(
                'Uploads never contain PHP. Pack the file into an archive outside the web root, delete it, '
                . 'then search the access log for its name and upload time to find the entry point.'
            ),
            'session-file' => __(
                'Planted session files are used to take over sessions (CosmicSting, SessionReaper). '
                . 'Archive and delete them, install the latest Magento security patches and check the admin logins of that time.'
            ),
            'foreign-ini' => __(
                'A .user.ini or php.ini in an upload directory can switch PHP back on or load code on every request. '
                . 'Archive and delete it.'
            ),
            'htaccess-php' => __(
                'An .htaccess that enables PHP in an upload directory prepares a backdoor. '
                . 'Archive and delete it, then check the directory for further files.'
            ),
            'php-in-image' => __(
                'An image with PHP code is a webshell waiting to be included. Archive and delete it, '
                . 'then search code and database for its file name.'
            ),
            'pub-root' => __(
                'Magento only needs index.php, cron.php, get.php, static.php and health_check.php in pub/. '
                . 'If you know the file, add it with its SHA-256 under "Allowed extra PHP files". Otherwise archive and delete it.'
            ),
            'pub-root-changed' => __(
                'The file differs from the approved version. Compare it with your copy. '
                . 'If nobody on your team changed it, treat it as a backdoor.'
            ),
            'index-php' => __(
                'Attackers modify pub/index.php to steal payment data. '
                . 'Restore it from your release or from vendor/magento/magento2-base/pub/index.php.'
            ),
            'report-payload' => __(
                'StyleSmuggler stage 1: the attack code was written into an error report. Make sure the hotfix '
                . 'APSB26-146 is installed (see system check), archive the report and check processes and crontab for stage 2.'
            ),
            'log-payload' => __(
                'Attack strings in logs are usually failed attempts. If the system check shows the StyleSmuggler '
                . 'hotfix as installed, nothing else needs to be done. Old entries disappear with log rotation.'
            ),
            'process-kthread' => $process,
            'process-tmp' => $process,
            'process-malware' => $process,
            'process-fccache' => __(
                'Check the command line. fc-cache is rarely run by the shop user; StyleSmuggler disguises its backdoor '
                . 'with this name. If it runs from /tmp or a deleted file, treat it as a backdoor.'
            ),
            'crontab' => __(
                'A crontab entry that downloads and runs code keeps the attacker in. Save the line, remove it with '
                . 'crontab -e, then look for the file it starts.'
            ),
            'content' => __(
                'Open the record in the admin and look for script code nobody on your team added. '
                . 'Obfuscated JavaScript in CMS or configuration is typical for card skimmers.'
            ),
            'admin-user' => __(
                'Confirm the user with your team. If nobody knows it, disable it, change all admin passwords '
                . 'and check what it did (admin action log).'
            ),
        ];
        return $advice[$check] ?? __('Check the finding manually.');
    }
}
