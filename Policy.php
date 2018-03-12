<?php
namespace EvesAddiction\Filestack;

class Policy {
  const ALLOWED_KEYS = [
    'call', 'container', 'expiry', 'handle',
    'maxSize', 'minSize', 'path', 'url'
  ];

  const VALID_CALLS = [
    'convert', 'exif', 'pick', 'read', 'remove',
    'stat', 'store', 'write', 'writeUrl',
  ];

  protected $call;
  protected $container;
  protected $expiry;
  protected $handle;
  protected $maxSize;
  protected $minSize;
  protected $path;
  protected $url;

  protected $_policy;
  protected $_base64;

  protected $_secret;
  protected $_signature;

  /**
   * Represents a filepicker Policy for access and request signing
   *
   * @param array $policyData
   */
  public function __construct(array $policyData) {
    foreach ($policyData as $option => $value) {
      if ($option == 'expiry') {
        $value = static::makeDateTimeImmutable($value);
      }

      $validOption = static::validateOption($option, $value, $exception);

      if ($validOption === true) {
        $this->{$option} = $value;
      } elseif ($exception instanceof PolicyException) {
        throw $exception;
      } else {
        throw new \RuntimeException('Unknown validation error');
      }
    }

    $this->_policy = $policyData;
  }

  /**
   * Get the base64-ed policy string (used in signing)
   *
   * @return string The base64 representation of the policy
   */
  public function getBase64() {
    if (!isset($this->_base64)) {
      $this->_base64 = static::makeBase64(json_encode($this->_policy));
    }

    return $this->_base64;
  }

  /**
   * Generate/get the HMAC signature for use in signed Filepicker requests
   *
   * @return string The signature
   */
  public function getSignature($secret) {
    $this->_secret = $secret;
    if (!isset($this->_signature)) {
      $this->_signature = static::makeSignature($this->getBase64(), $this->_secret);
    }

    return $this->_signature;
  }

  public function getExpiry() {
    return $this->expiry;
  }

  /**
   * Get the \DateInterval from $now when the Policy expires
   *
   * @param  \DateTimeInterface $now Optional datetime to compare against. Defaults to current date and time (using new \DateTimeImmutable())
   *
   * @return \DateInterval           The interval from $now when the policy will expire
   */
  public function getExpiryInterval(\DateTimeInterface $now = null) {
    if (is_null($now)) {
      $now = new \DateTimeImmutable();
    }

    return $now->diff($this->expiry);
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

    return $now >= $this->expiry;
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
      $expiry = $time_or_interval;
    } elseif ($time_or_interval instanceof \DateInterval) {
      $expiry = $now->add($time_or_interval);
    } else {
      throw new \InvalidArgumentException('Need some sort of date-y, time-y object');
    }

    if (!isset($this->_secret)) {
      throw new PolicyException("This policy hasn't been signed yet, so it can't be renewed!");
    }

    return new Policy($this->call, $expiry, $this->_path, $this->_secret);
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

    return str_replace(array('+', '/'), array('-', '_'), base64_encode($policy));
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

  public static function validateOption($option, $value, &$exception = null) {
    $exception = null; // in case a non-null value gets passed in

    if (!in_array($option, static::ALLOWED_KEYS)) {
      $exception = new PolicyException(sprintf('Invalid security policy option: "%s" is not one of %s', $option, implode(', ', static::ALLOWED_KEYS)));
      return false;
    }

    switch ($option) {
      case 'call':
        if (!is_array($value)) {
          $exception = new PolicyException('Invalid security policy allowed calls: "call" option must be an array');
        } else {
          $invalid_calls = array_diff((array) $value, static::VALID_CALLS);
          if (count($invalid_calls)) {
            $exception = new PolicyException(sprintf('Invalid security policy allowed calls: %s', implode(', ', $invalid_calls)));
          }
        }
        break;
      case 'expiry':
        if ($value instanceof \DateTimeInterface) {} else {
          $exception = new PolicyException('Invalid security policy expiry: must be \DateTimeInterface or date_parse()-able string');
        }
        break;
    }

    return is_null($exception) ? true : false;
  }

  /**
   * Tries to create a \DateTimeImmutable from a given input
   *
   * @param mixed $maybeDate Something that might be a date
   *
   * @throws PolicyException
   *
   * @return \DateTimeImmutable
   */
  public static function makeDateTimeImmutable($maybeDate) {
    switch (true) {
      case $maybeDate instanceof \DateTimeImmutable:
        $result = $maybeDate;
        break;
      case $maybeDate instanceof \DateTime:
        $result = \DateTimeImmutable::createFromMutable($maybeDate);
        break;
      case is_numeric($maybeDate) && $maybeDate >= 0:
        $result = new \DateTimeImmutable(sprintf('@%d', $maybeDate));
        break;
      default:
        try {
          $result = new \DateTimeImmutable($maybeDate);
        } catch (\Exception $e) {
          // The DateTime and DateTimeImmutable unhelpfully throw generic \Exception-s
          throw new PolicyException($e->getMessage(), $e->getCode(), $e);
        }
        break;
    }

    if (!isset($result)) {
      throw new PolicyException("Unknown issue parsing datetime");
    }

    return $result;
  }
}
