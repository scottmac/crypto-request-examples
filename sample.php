#!/usr/bin/env php
<?php

function base64_url_decode($input) {
  return base64_decode(strtr($input, '-_', '+/'));
}

function pkcs5_unpad($input) {
  $pad = ord($input[strlen($input)-1]);
  if ($pad > strlen($input)) {
    return $input;
  }
  if (strspn($input, chr($pad), strlen($input) - $pad) != $pad) {
    return $input;
  }
  return substr($input, 0, -1 * $pad);
}

function parse_signed_request($input, $secret, $max_age=3600) {
  list($encoded_sig, $encoded_envelope) = explode('.', $input, 2);
  $envelope = json_decode(base64_url_decode($encoded_envelope), true);
  $algorithm = $envelope['algorithm'];

  if ($algorithm != 'AES-256-CBC HMAC-SHA256' && $algorithm != 'HMAC-SHA256') {
    throw new Exception('Invalid request. (Unsupported algorithm.)');
  }

  if ($envelope['issued_at'] < time() - $max_age) {
    throw new Exception('Invalid request. (Too old.)');
  }

  if (base64_url_decode($encoded_sig) !=
        hash_hmac('sha256', $encoded_envelope, $secret, $raw=true)) {
    throw new Exception('Invalid request. (Invalid signature.)');
  }

  // for requests that are signed, but not encrypted, we're done
  if ($algorithm == 'HMAC-SHA256') {
    return $envelope;
  }

  $decrypted = false;
  if (function_exists('openssl_cipher_iv_length')) {
    $decrypted = openssl_decrypt(
      base64_url_decode($envelope['payload']),
      'aes-256-cbc',
      $secret,
      true,
      base64_url_decode($envelope['iv']));
  }

  if (!$decrypted) {
    $decrypted = mcrypt_decrypt(
      MCRYPT_RIJNDAEL_128,
      $secret,
      base64_url_decode($envelope['payload']),
      MCRYPT_MODE_CBC,
      base64_url_decode($envelope['iv']));
      $decrypted = pkcs5_unpad($decrypted);
  }

  // otherwise, decrypt the payload
  return json_decode(trim($decrypted), true);
}

// process from stdin
$input = fgets(fopen('php://stdin', 'r'));
$secret = '13750c9911fec5865d01f3bd00bdf4db';
try {
  echo json_encode(parse_signed_request($input, $secret));
} catch(Exception $e) {
  fwrite(fopen('php://stderr', 'w'), $e);
}
