#!/usr/local/bin/php
<?php
/* Add only explicitly listed, missing per-alias outbound NAT rules. */
require_once('script/load_phalcon.php');
use OPNsense\Core\Config;
if ($argc !== 3 || !in_array($argv[1], ['check', 'apply'], true)) {
    exit("Usage: AddAliasNAT.php check|apply mappings.json\n");
}
$rows = json_decode(file_get_contents($argv[2]), true, 512, JSON_THROW_ON_ERROR);
Config::getInstance()->lock();
$model = new OPNsense\Firewall\Filter();
$xml = Config::getInstance()->object();
$added = 0;
foreach ($rows as $row) {
    $interface = $row['assignment'];
    $alias = $row['alias'];
    if ((string)$xml->interfaces->{$interface}->descr !== $row['description']) {
        throw new RuntimeException('Interface identity mismatch');
    }
    $known = false;
    foreach ($xml->OPNsense->Firewall->Alias->aliases->alias as $item) {
        if ((string)$item->name === $alias) { $known = true; }
    }
    if (!$known) { throw new RuntimeException('Alias missing'); }
    $exists = false;
    foreach ($model->snatrules->rule->iterateItems() as $rule) {
        if ((string)$rule->interface === $interface && (string)$rule->source_net === $alias) {
            if ((string)$rule->enabled !== '1' || (string)$rule->nonat !== '0' ||
                (string)$rule->target !== '' || (string)$rule->destination_net !== 'any' ||
                (string)$rule->source_not !== '0' || (string)$rule->destination_not !== '0' ||
                (string)$rule->ipprotocol !== 'inet' || (string)$rule->protocol !== 'any' ||
                (string)$rule->source_port !== '' || (string)$rule->destination_port !== '') {
                throw new RuntimeException('Existing NAT needs review');
            }
            $exists = true;
        }
    }
    foreach ($xml->nat->outbound->rule as $rule) {
        if ((string)$rule->interface === $interface && (string)$rule->source->network === $alias) {
            throw new RuntimeException('Legacy NAT exists; review before adding');
        }
    }
    if ($exists) { echo $row['description'] . " already configured\n"; continue; }
    $rule = $model->snatrules->rule->add();
    $rule->setNodes(['enabled'=>'1','nonat'=>'0','sequence'=>'100',
        'interface'=>$interface,'ipprotocol'=>'inet','protocol'=>'any',
        'source_net'=>$alias,'source_not'=>'0','destination_net'=>'any',
        'destination_not'=>'0','target'=>'','staticnatport'=>'0',
        'description'=>$row['description'].' PureVPN WireGuard outbound NAT']);
    $added++;
}
if (count($model->performValidation()) > 0) { throw new RuntimeException('Validation failed; nothing saved'); }
if ($argv[1] === 'apply' && $added) {
    $model->serializeToConfig();
    Config::getInstance()->save();
}
echo "$added NAT additions " . $argv[1] . " validated\n";
