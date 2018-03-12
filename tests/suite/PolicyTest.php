<?php
// https://dev.filestack.com/apps/<APP_KEY>/security
use EvesAddiction\Filestack\Policy;

class PolicyTest extends TestCase {
  /**
   * @dataProvider policyJsonProvider
   */
  function testPolicy($policyData, $secret, $expectedBase64, $expectedHMAC) {
    $policy = new Policy($policyData);
    $this->assertEquals($expectedBase64, $policy->getBase64());
    $this->assertEquals($expectedHMAC, $policy->getSignature($secret));
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
        'secret' => '4ONR18TSCLA73W6BQ5FKY09VH',
        'Base64' => 'eyJleHBpcnkiOjE1MjU1MDAwMDAsImNhbGwiOlsicGljayIsInJlYWQiLCJzdGF0Iiwid3JpdGUiLCJ3cml0ZVVybCIsInN0b3JlIiwiY29udmVydCIsInJlbW92ZSIsImV4aWYiXSwiaGFuZGxlIjoiRm9vQmFyQmF6IiwicGF0aCI6Ilwvc29tZVwvcGF0aFwvKiIsImNvbnRhaW5lciI6InNvbWVcL2J1Y2tldFwvKiIsIm1pblNpemUiOiIxMjgiLCJtYXhTaXplIjoiMTAyNDAwMCJ9',
        'HMAC-SHA256(hex)' => '31e6af870e44627750b8b9eb9330007404e34f436910e28afa0fecffecc9dcb5',
      ]
    ];
  }
}
