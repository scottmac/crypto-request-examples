#!/usr/bin/env php
<?php

function base64_url_encode($input) {
  $str = strtr(base64_encode($input), '+/=', '-_.');
  $str = str_replace('.', '', $str); // remove padding
  return $str;
}

function pkcs5_pad($input, $blocksize) {
  $pad = $blocksize - (strlen($input) % $blocksize);
  return $input . str_repeat(chr($pad), $pad);
}

function encrypt_data($data, $secret) {
  $data = json_encode($data);
  if (function_exists('openssl_cipher_iv_length')) {
    $mode = 'aes-256-cbc';
    $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($mode));
    $ed = openssl_encrypt(
      $data,
      $mode,
      $secret,
      true,
      $iv);
  } else {
    $cipher = MCRYPT_RIJNDAEL_128;
    $mode = MCRYPT_MODE_CBC;

    $data = pkcs5_pad($data, mcrypt_get_block_size($cipher, $mode));

    $iv = mcrypt_create_iv(
      mcrypt_get_iv_size($cipher, $mode), MCRYPT_DEV_URANDOM);
    $ed = mcrypt_encrypt(
      $cipher, $secret, $data, $mode, $iv);
  }
  
  return array(
    'payload' => base64_url_encode($ed),
    'iv' => base64_url_encode($iv),
  );
}

function generate_signed_request($data, $secret, $encrypt=false) {
  // wrap data inside payload if we are encrypting
  if ($encrypt) {
    $data = encrypt_data($data, $secret);
  }

  // always present, and always at the top level
  $data['algorithm'] = $encrypt ? 'AES-256-CBC HMAC-SHA256' : 'HMAC-SHA256';
  $data['issued_at'] = time();

  // sign it
  $payload = base64_url_encode(json_encode($data));
  $sig = base64_url_encode(
    hash_hmac('sha256', $payload, $secret, $raw=true));
  return $sig.'.'.$payload;
}

$secret = '13750c9911fec5865d01f3bd00bdf4db';
echo generate_signed_request(
  array('the' => array('answer' => "the answer is forty two")),
  $secret,
  $_SERVER['DO_ENCRYPT'] == '1');
