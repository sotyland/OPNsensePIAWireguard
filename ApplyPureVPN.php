#!/usr/local/bin/php
<?php
/* Validated, scoped native model update. Input contains secrets; keep root-only. */
require_once('script/load_phalcon.php');
use OPNsense\Core\Config;
if ($argc !== 3 || !in_array($argv[1], ['check', 'apply'], true)) {
    exit("Usage: ApplyPureVPN.php check|apply private-payload.json\n");
}
$data = json_decode(file_get_contents($argv[2]), true, 512, JSON_THROW_ON_ERROR);
if (array_diff(array_keys($data['server']), ['privkey', 'pubkey', 'tunneladdress', 'gateway']) ||
    array_diff(array_keys($data['peer']), ['pubkey', 'psk', 'tunneladdress', 'serveraddress', 'serverport', 'keepalive'])) {
    throw new RuntimeException('Unexpected mutation fields');
}
Config::getInstance()->lock();
$serverModel = new OPNsense\Wireguard\Server();
$peerModel = new OPNsense\Wireguard\Client();
$gatewayModel = new OPNsense\Routing\Gateways();
$server = $serverModel->getNodeByReference('servers.server.' . $data['uuid']);
$peer = $peerModel->getNodeByReference('clients.client.' . $data['peer_uuid']);
$gateway = $gatewayModel->getNodeByReference('gateway_item.' . $data['gateway_uuid']);
if (!$server || !$peer || !$gateway || (string)$server->name !== $data['name'] ||
    (string)$server->peers !== $data['peer_uuid'] ||
    'wg' . (string)$server->instance !== $data['interface'] ||
    (string)$gateway->interface !== $data['assignment']) {
    throw new RuntimeException('Object identity check failed');
}
foreach ($serverModel->servers->server->iterateItems() as $id => $other) {
    if ($id !== $data['uuid'] && in_array($data['peer_uuid'], explode(',', (string)$other->peers), true)) {
        throw new RuntimeException('Shared peer; refusing update');
    }
}
$server->setNodes($data['server']);
$peer->setNodes($data['peer']);
$gateway->setNodes(['gateway' => $data['gateway'], 'fargw' => '1']);
foreach ([$serverModel, $peerModel, $gatewayModel] as $model) {
    if (count($model->performValidation()) > 0) {
        throw new RuntimeException('Model validation failed; nothing saved');
    }
}
if ($argv[1] === 'apply') {
    $serverModel->serializeToConfig();
    $peerModel->serializeToConfig();
    $gatewayModel->serializeToConfig();
    Config::getInstance()->save();
}
echo $data['name'] . ' ' . $argv[1] . " validated\n";
