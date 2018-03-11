<?php
// https://dev.filestack.com/apps/<APP_KEY>/security
use EvesAddiction\Filestack\Policy;

class FooTest extends TestCase {
  /**
   * @dataProvider policyJsonProvider
   */
  function testBase64($policyData, $expectedBase64, $expectedHMAC) {
    $policy = new Policy($policyData);
    $this->assertEquals($expectedBase64, $policy->getBase64());
  }

  function policyJsonProvider() {
    return [
      'A policy with everything' => [
        'policy' => [
          "expiry"    => 1525500000,
          "call"      => [ "pick", "read", "stat", "write", "writeUrl", "store",
                          "convert", "remove", "exif", ],
          "handle"    => "FooBarBaz",
          "path"      => "/some/path/*",
          "container" => "some/bucket/*",
          "minSize"   => "128",
          "maxSize"   => "1024000",
        ],
        'Base64' => 'eyJleHBpcnkiOjE1MjU1MDAwMDAsImNhbGwiOlsicGljayIsInJlYWQiLCJzdGF0Iiwid3JpdGUiLCJ3cml0ZVVybCIsInN0b3JlIiwiY29udmVydCIsInJlbW92ZSIsImV4aWYiXSwiaGFuZGxlIjoiRm9vQmFyQmF6IiwicGF0aCI6Ii9zb21lL3BhdGgvKiIsImNvbnRhaW5lciI6InNvbWUvYnVja2V0LyoiLCJtaW5TaXplIjoiMTI4IiwibWF4U2l6ZSI6IjEwMjQwMDAifQ==',
        'HMAC-SHA256(hex)' => '3d93d83ff2f3e5298b2bd833d5b88d28eaca7505cb14516ef3ef6baacaa3cc34',
      ]
    ];
  }
}
