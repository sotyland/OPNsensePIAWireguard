#!/usr/local/bin/php
<?php
/* Replace invalid gateway-address ping checks with the separately installed WG monitor. */
require_once('script/load_phalcon.php');
use OPNsense\Core\Config;
if ($argc !== 3 || !in_array($argv[1], ['check', 'apply'], true)) {
    exit("Usage: ConfigurePureVPNGatewayHealth.php check|apply managed.json\n");
}
$managed = json_decode(file_get_contents($argv[2]), true, 512, JSON_THROW_ON_ERROR);
Config::getInstance()->lock();
$servers = new OPNsense\Wireguard\Server();
$gateways = new OPNsense\Routing\Gateways();
$xml = Config::getInstance()->object();
$changed = 0;
foreach ($managed as $entry) {
    $server = $servers->getNodeByReference('servers.server.' . $entry['uuid']);
    if (!$server || (string)$server->name !== $entry['name'] ||
        'wg' . (string)$server->instance !== $entry['interface'] ||
        (string)$server->peers !== $entry['peer_uuid']) {
        throw new RuntimeException('Managed identity mismatch');
    }
    $assignment = null;
    foreach ($xml->interfaces->children() as $key => $interface) {
        if ((string)$interface->if === $entry['interface']) { $assignment = $key; }
    }
    if ($assignment === null) { throw new RuntimeException('Assignment missing'); }
    $matches = [];
    foreach ($gateways->gateway_item->iterateItems() as $gateway) {
        if ((string)$gateway->interface === $assignment && (string)$gateway->ipprotocol === 'inet') {
            $matches[] = $gateway;
        }
    }
    if (count($matches) !== 1 || (string)$matches[0]->gateway !== (string)$server->gateway ||
        (string)$matches[0]->monitor !== '') {
        throw new RuntimeException('Gateway or custom monitor mismatch');
    }
    if ((string)$matches[0]->monitor_disable !== '1') {
        $matches[0]->monitor_disable = '1';
        $changed++;
    }
}
if (count($gateways->performValidation()) > 0) { throw new RuntimeException('Validation failed'); }
if ($argv[1] === 'apply' && $changed) {
    $gateways->serializeToConfig();
    Config::getInstance()->save();
}
echo "$changed gateway ping checks replaced " . $argv[1] . " validated\n";
