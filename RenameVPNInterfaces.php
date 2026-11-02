#!/usr/local/bin/php
<?php
/* Display labels only: no device, address, rule or alias mutation. */
require_once('script/load_phalcon.php');
use OPNsense\Core\Config;
if ($argc !== 2 || !in_array($argv[1], ['check', 'apply'], true)) {
    exit("Usage: RenameVPNInterfaces.php check|apply\n");
}
$mapping = [
    'opt3'=>['wg1','PIASofia','Sofia'],
    'opt4'=>['wg2','PIALondon','London'],
    'opt5'=>['wg3','PIANewJersey','NewJersey'],
    'opt7'=>['wg4','PIASerbia','Serbia'],
    'opt8'=>['wg5','PIASlovakia','Slovakia'],
    'opt9'=>['wg6','PIARomania','Romania'],
    'opt10'=>['wg7','PIAPortugal','Portugal'],
    'opt11'=>['wg8','PIAMalta','Italy'],
    'opt12'=>['wg9','PIALuxembourg','Luxembourg'],
    'opt13'=>['wg10','PIABaltimore','WashingtonDC'],
];
Config::getInstance()->lock();
$xml = Config::getInstance()->object();
foreach ($mapping as $key => [$device, $old, $new]) {
    $interface = $xml->interfaces->{$key};
    if ((string)$interface->if !== $device || !in_array((string)$interface->descr, [$old, $new], true)) {
        throw new RuntimeException('Interface identity mismatch: ' . $key);
    }
    foreach ($xml->interfaces->children() as $otherKey => $other) {
        if ($otherKey !== $key && strcasecmp((string)$other->descr, $new) === 0) {
            throw new RuntimeException('Duplicate interface label: ' . $new);
        }
    }
}
$changed = 0;
foreach ($mapping as $key => [$device, $old, $new]) {
    if ((string)$xml->interfaces->{$key}->descr !== $new) {
        $xml->interfaces->{$key}->descr = $new;
        $changed++;
    }
    echo "$key $device $new\n";
}
if ($argv[1] === 'apply' && $changed) { Config::getInstance()->save(); }
echo "$changed display labels " . $argv[1] . " validated\n";
