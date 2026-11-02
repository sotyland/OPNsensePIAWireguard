#!/usr/local/bin/php
<?php
require_once('script/load_phalcon.php');
use OPNsense\Core\Config;
if ($argc !== 2 || !in_array($argv[1], ['check', 'enable', 'disable'], true)) {
    exit("Usage: ConfigurePureVPNCron.php check|enable|disable\n");
}
Config::getInstance()->lock();
$model = new OPNsense\Cron\Cron();
$job = null;
foreach ($model->jobs->job->iterateItems() as $item) {
    if ((string)$item->command === 'purevpn monitor') {
        if ($job !== null) { throw new RuntimeException('Duplicate monitor jobs'); }
        $job = $item;
    }
}
if ($job === null) { $job = $model->jobs->job->add(); }
$job->setNodes(['origin'=>'cron','enabled'=>$argv[1] === 'enable' ? '1':'0',
    'minutes'=>'*','hours'=>'*','days'=>'*','months'=>'*','weekdays'=>'*',
    'who'=>'root','command'=>'purevpn monitor','parameters'=>'',
    'description'=>'PureVPN Monitor - scoped automatic WireGuard recovery']);
if (count($model->performValidation()) > 0) { throw new RuntimeException('Cron validation failed'); }
if ($argv[1] !== 'check') {
    $model->serializeToConfig();
    Config::getInstance()->save();
}
echo 'PureVPN Monitor ' . $argv[1] . " validated\n";
