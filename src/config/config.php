<?php

return [
    'enabled' => true,
    'driver' => 'clamd',
    'clamd' => [
        'socket' => 'unix:///var/run/clamav/clamd.ctl',
        'streamMaxLength' => 26214400,
    ],
];
