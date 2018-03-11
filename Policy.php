<?php
namespace EvesAddiction\Filestack;

class Policy {
  protected $calls = [];
  protected $expires;
  protected $path;

  protected $_policy;
  protected $_base64;

  protected $_secret;
  protected $_signature;

  /**
   * Represents a filepicker Policy for access and request signing
   *
   * @param array              $calls
   * @param \DateTimeInterface $expires
   * @param string             $path
   * @param string|null        $secret
   */
  public function __construct(array $calls, \DateTimeInterface $expires, $path = '.*', $secret = null) {
    $this->calls = $calls;
    $this->expires = $expires instanceof \DateTimeImmutable ? $expires : \DateTimeImmutable::createFromMutable($expires);
    $this->path = $path;
    $this->_secret = $secret;

    $this->_policy = [ 'expiry' => $expires->getTimestamp(),
      'calls'  => $calls,
    ];

    if (strlen($path)) {
      $this->_policy['path'] = $path;
    }
  }

  /**
   * Get the base64-ed policy string (used in signing)
   *
   * @return string The base64 representation of the policy
   */
  public function getBase64() {
    if (!isset($this->_base64)) {
      $this->_base64 = static::makeBase64($this->_policy);
    }

    return $this->_base64;
  }

  /**
   * Generate/get the HMAC signature for use in signed Filepicker requests
   *
   * @return string The signature
   */
  public function getSignature() {
    if (!isset($this->_signature)) {
      $this->_signature = static::makeSignature($this->getBase64(), $this->_secret);
    }

    return $this->_signature;
  }

  public function getExpires() {
    return $this->expires;
  }

  /**
   * Get the \DateInterval from $now when the Policy expires
   *
   * @param  \DateTimeInterface $now Optional datetime to compare against. Defaults to current date and time (using new \DateTimeImmutable())
   *
   * @return \DateInterval           The interval from $now when the policy will expire
   */
  public function getExpiresInterval(\DateTimeInterface $now = null) {
    if (is_null($now)) {
      $now = new \DateTimeImmutable();
    }

    return $now->diff($this->expires);
  }

  /**
   * Whether the Policy is expired as of $now
   *
   * @param \DateTimeInterface $now Datetime to compare against
   * @return boolean                Is it expired $now?
   */
  public function isExpired(\DateTimeInterface $now = null) {
    if (is_null($now)) {
      $now = new \DateTimeImmutable();
    }

    return $now >= $this->expires;
  }

  /**
   * Create a new Policy from this one with expiry of $time_or_interval
   *
   * @param \DateTimeInterface|\DateInterval $time_or_interval Datetime (or DateInterval from $now) at which the new policy will expire
   * @param \DateTimeInterface               $now              Optional base time for computing expiry if $time_or_interval is an interval. Defaults to now
   *
   * @return EvesAddiction\Filestack\Policy                   The new Policy
   */
  public function renew($time_or_interval, $now = null) {
    if (is_null($now)) {
      $now = new DateTimeImmutable();
    }

    if ($time_or_interval instanceof \DateTimeInterface) {
      $expires = $time_or_interval;
    } elseif ($time_or_interval instanceof \DateInterval) {
      $expires = $now->add($time_or_interval);
    } else {
      throw new \InvalidArgumentException('Need some sort of date-y, time-y object');
    }

    return new Policy($this->calls, $expires, $this->_path, $this->_secret);
  }

  public function signUrl($url) {}

  // Static Methods

  /**
   * Make the base64 digest for a Policy or an array representing $policy->_policy
   *
   * @param Policy|array $policy ¯\_(ツ)_/¯
   *
   * @return string              The base64 digest of the policy, for use in signing
   */
  public static function makeBase64($policy) {
    if ($policy instanceof Policy) {
      $policy = $policy->_policy;
    }

    return str_replace(array('+', '/'), array('-', '_'), base64_encode(json_encode($policy)));
  }

  /**
   * Sign a policy
   *
   * @param Policy|array $policy
   * @param string|null  $secret
   *
   * @return void
   */
  public static function makeSignature($policy, $secret) {
    if ($policy instanceof Policy) {
      $base64 = $policy->getBase64();
    } elseif (is_array($policy)) {
      $base64 = static::makeBase64($policy);
    } else {
      $base64 = $policy;
    }

    return hash_hmac('sha256', $base64, $secret);
  }
}
