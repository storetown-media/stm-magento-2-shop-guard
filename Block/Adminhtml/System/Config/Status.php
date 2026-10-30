<?php
/**
 * Copyright (c) Storetown Media. All rights reserved.
 * See LICENSE for license details.
 */
declare(strict_types=1);

namespace Storetown\ShopGuard\Block\Adminhtml\System\Config;

use Magento\Backend\Block\Template\Context;
use Magento\Config\Block\System\Config\Form\Field;
use Magento\Framework\Data\Form\Element\AbstractElement;
use Magento\Framework\DataObject;
use Magento\Framework\View\Helper\SecureHtmlRenderer;
use Storetown\ShopGuard\Model\Config;
use Storetown\ShopGuard\Model\FileScanner;
use Storetown\ShopGuard\Model\Integrity;
use Storetown\ShopGuard\Model\RuleList;
use Storetown\ShopGuard\Model\RuntimeSnapshot;
use Storetown\ShopGuard\Model\ClientIp;
use Storetown\ShopGuard\Model\SystemCheck;

/**
 * Status overview at the top of the configuration page. Rendered by PHP-FPM, so the PHP values are the real ones.
 * Dispatches "storetown_shop_guard_status" with a DataObject "summary"; an add-on may set headline, detail, level,
 * overview_url, license_url and links (settings group => [label, url]) to tie its own pages to this one.
 */
class Status extends Field
{
    /**
     * @param Context $context
     * @param SystemCheck $systemCheck
     * @param FileScanner $scanner
     * @param Config $config
     * @param Integrity $integrity
     * @param SecureHtmlRenderer $secureRenderer
     * @param array $data
     */
    public function __construct(
        Context $context,
        private SystemCheck $systemCheck,
        private FileScanner $scanner,
        private Config $config,
        private Integrity $integrity,
        private SecureHtmlRenderer $secureRenderer,
        array $data = []
    ) {
        parent::__construct($context, $data, $secureRenderer);
    }

    /**
     * @param AbstractElement $element
     * @return string
     */
    public function render(AbstractElement $element)
    {
        // Shop Security Guard Pro fills in its verdict, the link to its overview and one link per settings group
        $summary = new DataObject(['links' => []]);
        $this->_eventManager->dispatch('storetown_shop_guard_status', ['summary' => $summary]);
        $colors = [SystemCheck::OK => '#185b00', SystemCheck::WARNING => '#8a5300', SystemCheck::CRITICAL => '#b30000'];
        $details = $this->findingsHtml($colors) . $this->tableHtml($colors);
        $html = '<tr><td colspan="4">' . $this->barHtml($summary);
        if ((string)$summary->getData('headline') !== '') {
            // the overview of Pro shows all of it, here it would only repeat it
            $html .= $this->verdictHtml($summary) . sprintf(
                '<details class="sgc-details"><summary>%s</summary>%s</details>',
                $this->escapeHtml(__('Backdoor scan and system values')),
                $details
            );
        } else {
            $html .= $details;
        }
        return $html . $this->scriptHtml($summary) . '</td></tr>';
    }

    /**
     * System values, last file scan, reference state, blocks and the IP the shop sees
     *
     * @param array<string, string> $colors
     * @return string
     */
    private function tableHtml(array $colors): string
    {
        $html = '<table class="admin__table-secondary" style="width:100%"><tbody>';
        foreach ($this->systemCheck->run(RuntimeSnapshot::current()) as $row) {
            $html .= sprintf(
                '<tr><th style="width:28%%">%s</th><td style="width:22%%;color:%s;font-weight:600">%s</td><td>%s</td></tr>',
                $this->escapeHtml((string)$row['label']),
                $colors[$row['level']],
                $this->escapeHtml($row['value']),
                $this->escapeHtml((string)$row['hint'])
            );
        }

        $state = $this->scanner->state();
        $html .= sprintf(
            '<tr><th>%s</th><td>%s</td><td>%s</td></tr>',
            $this->escapeHtml(__('Last file scan')),
            empty($state['last']) ? '–' : $this->escapeHtml($this->_localeDate->date((int)$state['last'])->format('d.m.Y H:i')),
            empty($state['last']) ? $this->escapeHtml(__('Runs by cron every 30 minutes.'))
                : $this->escapeHtml((int)($state['findings'] ?? 0) === 1
                    ? __('1 finding')
                    : __('%1 findings', (int)($state['findings'] ?? 0)))
        );
        $integrity = $this->integrity->state();
        $html .= sprintf(
            '<tr><th>%s</th><td>%s</td><td>%s</td></tr>',
            $this->escapeHtml(__('Reference state of the code')),
            empty($integrity['accepted']) ? '–' : $this->escapeHtml(
                $this->_localeDate->date((int)$integrity['accepted'])->format('d.m.Y H:i')
            ),
            $this->escapeHtml(empty($integrity['accepted'])
                ? __('Created with the first file scan.')
                : __(
                    '%1 code files. After a deployment: bin/magento shopguard:integrity --accept',
                    number_format((int)($integrity['files'] ?? 0), 0, ',', '.')
                ))
        );
        $html .= sprintf(
            '<tr><th>%s</th><td>%d / %d</td><td>%s</td></tr>',
            $this->escapeHtml(__('Automatic blocks')),
            count(RuleList::parse($this->config->value(Config::AUTO_IPS))),
            count(RuleList::parse($this->config->value(Config::AUTO_AGENTS))),
            $this->escapeHtml(__('IP addresses / user agents, see "Bot scan" below'))
        );

        $request = $this->getRequest();
        $ips = [];
        foreach (['REMOTE_ADDR', 'HTTP_X_REAL_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_CF_CONNECTING_IP'] as $key) {
            $value = (string)$request->getServer($key);
            if ($value !== '') {
                $ips[] = str_replace('HTTP_', '', $key) . ' = ' . $value;
            }
        }
        $behindProxy = $this->config->value(Config::IP_SOURCE) === 'remote_addr'
            && ClientIp::isProxyAddress(
                (string)$request->getServer('REMOTE_ADDR'),
                (string)$request->getServer('SERVER_ADDR')
            );
        $html .= sprintf(
            '<tr><th>%s</th><td colspan="2"%s>%s<br><small>%s</small></td></tr>',
            $this->escapeHtml(__('Your IP as seen by the shop')),
            $behindProxy ? ' style="color:#8a5300"' : '',
            $this->escapeHtml(implode(' | ', $ips)),
            $this->escapeHtml($behindProxy
                ? __('REMOTE_ADDR is a proxy or server address. IP blocking is inactive until "Client IP from" is set.')
                : __('If REMOTE_ADDR is a server address, set "Client IP from" to the header that shows your IP.'))
        );
        return $html . '</tbody></table>';
    }

    /**
     * The bar Shop Security Guard shows above its settings and above the overview of Pro: name, pages, protection
     *
     * @param DataObject $summary
     * @return string
     */
    private function barHtml(DataObject $summary): string
    {
        $tabs = '';
        if ($summary->getData('overview_url')) {
            $tabs = sprintf(
                '<a class="sgc-bar__tab" href="%s">%s</a><span class="sgc-bar__tab is-current" aria-current="page">%s</span>',
                $this->escapeUrl((string)$summary->getData('overview_url')),
                $this->escapeHtml(__('Overview')),
                $this->escapeHtml(__('Settings'))
            );
            if ($summary->getData('license_url')) {
                $tabs .= sprintf(
                    '<a class="sgc-bar__tab" href="%s">%s</a>',
                    $this->escapeUrl((string)$summary->getData('license_url')),
                    $this->escapeHtml(__('License'))
                );
            }
        }
        $on = $this->config->flag(Config::ENABLED) && $this->config->flag(Config::ATTACK_RULES);
        return '<style>'
            . '.sgc-bar{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:6px 24px;'
            . 'border-bottom:1px solid #e3e6ea;margin:0 0 22px}'
            . '.sgc-bar__left{display:flex;align-items:center;flex-wrap:wrap;gap:0 30px}'
            . '.sgc-bar__name{font-size:1.8rem;font-weight:600;color:#1d2226;padding:10px 0}'
            . '.sgc-bar__tab{display:block;padding:11px 0;margin-bottom:-1px;border-bottom:3px solid transparent;'
            . 'color:#6b7580;font-size:1.45rem;text-decoration:none}'
            . 'a.sgc-bar__tab:hover{color:#1d2226;border-bottom-color:#c9ced4;text-decoration:none}'
            . '.sgc-bar__tab.is-current{color:#1d2226;font-weight:600;border-bottom-color:#f05400}'
            . '.sgc-bar__state{margin:0;font-size:1.35rem;font-weight:600;display:flex;align-items:center;gap:8px}'
            . '.sgc-bar__state:before{content:"";width:8px;height:8px;background:currentColor}'
            . '.sgc-verdict{border-left:4px solid #9a5b06;background:#fbf2e2;padding:12px 18px;margin:0 0 18px;'
            . 'display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px 24px}'
            . '.sgc-verdict--ok{border-left-color:#1f7a45;background:#e9f4ed}'
            . '.sgc-verdict--critical{border-left-color:#b42318;background:#fcece9}'
            . '.sgc-verdict__head{margin:0;font-size:1.7rem;font-weight:600;color:#1d2226}'
            . '.sgc-verdict__detail{margin:2px 0 0;color:#3a434b}'
            . '.sgc-verdict__link{font-weight:600;white-space:nowrap}'
            . '.sgc-details{margin:0 0 6px}.sgc-details>summary{cursor:pointer;color:#2f6db5;text-decoration:underline;text-underline-offset:3px;margin:0 0 14px}'
            . '.sgc-glink{position:absolute;right:48px;top:50%;transform:translateY(-50%);font-size:1.3rem;'
            . 'font-weight:400}.sgc-glink a{color:#2f6db5}'
            . '@media (max-width:767px){.sgc-glink{position:static;transform:none;display:block;padding:0 0 10px 20px}}'
            . '</style>'
            . sprintf(
                '<div class="sgc-bar"><div class="sgc-bar__left"><span class="sgc-bar__name">Shop Security Guard</span>'
                . '<nav style="display:flex;gap:0 30px">%s</nav></div><p class="sgc-bar__state" style="color:%s">%s</p></div>',
                $tabs,
                $on ? '#1f7a45' : '#b42318',
                $this->escapeHtml($on ? __('Protection active') : __('Request filter off'))
            );
    }

    /**
     * The verdict of Shop Security Guard Pro in one line, with the way to its overview
     *
     * @param DataObject $summary
     * @return string
     */
    private function verdictHtml(DataObject $summary): string
    {
        $level = in_array($summary->getData('level'), [SystemCheck::OK, SystemCheck::CRITICAL], true)
            ? (string)$summary->getData('level') : SystemCheck::WARNING;
        return sprintf(
            '<div class="sgc-verdict sgc-verdict--%s"><div><p class="sgc-verdict__head">%s</p>'
            . '<p class="sgc-verdict__detail">%s</p></div><a class="sgc-verdict__link" href="%s">%s</a></div>',
            $level,
            $this->escapeHtml((string)$summary->getData('headline')),
            $this->escapeHtml((string)$summary->getData('detail')),
            $this->escapeUrl((string)$summary->getData('overview_url')),
            $this->escapeHtml(__('To the overview'))
        );
    }

    /**
     * Links from the settings groups to the matching view of the overview, and #sg-<group> opens that group
     *
     * @param DataObject $summary
     * @return string
     */
    private function scriptHtml(DataObject $summary): string
    {
        $links = [];
        foreach ((array)$summary->getData('links') as $group => $link) {
            if (preg_match('/^[a-z_]+$/', (string)$group) && isset($link['label'], $link['url'])) {
                $links[$group] = ['label' => (string)$link['label'], 'url' => (string)$link['url']];
            }
        }
        $script = 'require(["domReady!"],function(){var links=' . json_encode($links, JSON_HEX_TAG | JSON_HEX_AMP)
            . ';Object.keys(links).forEach(function(g){var head=document.getElementById("shop_guard_"+g+"-head");'
            . 'if(!head){return;}var s=document.createElement("span"),a=document.createElement("a");s.className="sgc-glink";'
            . 'a.href=links[g].url;a.textContent=links[g].label;s.appendChild(a);'
            . 'head.parentNode.style.position="relative";head.parentNode.appendChild(s);});'
            . 'var m=/^#sg-([a-z_]+)$/.exec(location.hash);if(!m){return;}'
            . 'var head=document.getElementById("shop_guard_"+m[1]+"-head");if(!head){return;}'
            . 'if(!head.classList.contains("open")){head.click();}'
            . 'setTimeout(function(){head.scrollIntoView({block:"start"});window.scrollBy(0,-90);},150);});';
        return $this->secureRenderer->renderTag('script', [], $script, false);
    }

    /**
     * Result of the last backdoor scan in plain words, with what to do per finding.
     *
     * @param array<string, string> $colors
     * @return string
     */
    private function findingsHtml(array $colors): string
    {
        $state = $this->scanner->state();
        if (empty($state['last'])) {
            return sprintf(
                '<p style="font-size:1.6rem;margin:0 0 1.5rem">%s</p>',
                $this->escapeHtml(__('No scan yet. The first backdoor scan runs with the next cron run (every 30 minutes).'))
            );
        }
        $findings = $this->scanner->lastFindings();
        $critical = (int)($state['critical'] ?? 0);
        $warnings = count($findings) - $critical;
        if (!$findings) {
            $headline = __('No dangerous files found.');
            $color = $colors[SystemCheck::OK];
        } elseif ($critical) {
            $headline = ($critical === 1 ? __('1 critical finding') : __('%1 critical findings', $critical))
                . ($warnings ? ', ' . ($warnings === 1 ? __('1 warning') : __('%1 warnings', $warnings)) : '')
                . '. ' . __('Please act now.');
            $color = $colors[SystemCheck::CRITICAL];
        } else {
            $headline = $warnings === 1 ? __('1 warning, nothing critical.') : __('%1 warnings, nothing critical.', $warnings);
            $color = $colors[SystemCheck::WARNING];
        }
        $html = sprintf(
            '<p style="font-size:1.8rem;font-weight:600;color:%s;margin:0 0 .3rem">%s</p>'
            . '<p style="margin:0 0 1.5rem;color:#666">%s</p>',
            $color,
            $this->escapeHtml($headline),
            $this->escapeHtml(__(
                'Last backdoor scan: %1',
                $this->_localeDate->date((int)$state['last'])->format('d.m.Y H:i')
            ))
        );

        $byCheck = [];
        foreach ($findings as $finding) {
            $byCheck[$finding['check']][] = $finding;
        }
        foreach ($byCheck as $check => $group) {
            $paths = array_map(fn ($f) => $this->escapeHtml($f['path']), array_slice($group, 0, 5));
            if (count($group) > 5) {
                $paths[] = $this->escapeHtml(__('and %1 more', count($group) - 5));
            }
            $html .= sprintf(
                '<div style="border-left:3px solid %s;padding:.2rem 0 .2rem 1.2rem;margin:0 0 1.5rem">'
                . '<strong>%s</strong><br><code style="font-size:1.2rem">%s</code>'
                . '<p style="margin:.5rem 0 0"><strong>%s</strong> %s</p></div>',
                $colors[$group[0]['level'] === FileScanner::CRITICAL ? SystemCheck::CRITICAL : SystemCheck::WARNING],
                $this->escapeHtml((string)$group[0]['text']),
                implode('<br>', $paths),
                $this->escapeHtml(__('What to do:')),
                $this->escapeHtml((string)$group[0]['advice'])
            );
        }
        return $html;
    }
}
