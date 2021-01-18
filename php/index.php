<?php
/* This file is part of BrokerService
 *
 * BrokerService is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * BrokerService is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with BrokerService. If not, see <https://www.gnu.org/licenses/>.
 */

$cookie_name="brokerservice";
$encryption_key="E8xQtbeeBCsB72U9K4idrMdRj0xiLjZp";
$cipher = "aes-128-cbc";

// immediately bail if this is not a GET
if($_SERVER['REQUEST_METHOD'] !== 'GET') exit_403();

// immediately bail if this is not https
if(empty($_SERVER['HTTPS'])) exit_403();

// read the user cookie to determine the callback URLs
$cookie = isset($_COOKIE[$cookie_name]) ? b64_decode($_COOKIE[$cookie_name]) : null;

// read the URL parameters
$base = isset($_GET["base"]) ? b64_decode($_GET["base"]) : null;
$site = isset($_GET["site"]) ? b64_decode($_GET["site"]) : null;
$action = isset($_GET["action"]) ? b64_decode($_GET["action"]) : null;
$cb = isset($_GET["cb"]) ? b64_decode($_GET["cb"]) : null;

// validate the action value
$action2 = preg_replace("/[^-a-zA-Z0-9\.]/","",$action);
if(strcmp($action,$action2)) exit_403();

// determine the host name
$hostname = $_SERVER['HTTP_HOST'];

// base and site should be set
if(empty($base) || empty($site)) exit_403();

// determine the action to take: register or everything-else
if($_SERVER['REQUEST_URI'] === '/register') {
    do_register($base, $site);
}
else if(!empty($cookie)) {
    do_action($cookie, $base, $site, $action, $cb);
}
else {
    exit_403();
}

// unconditional end of processing here
exit;

function do_action($cookie, $base,$site, $action, $cb) {
    // cookie contains the full site we need to redirect to
    // base contains the remote site base domain (https://www.example.com)
    // site contains the remote site content path
    // action is a free form string (already validated)
    
    // decode cookie and base
    $cookie = do_decrypt($cookie);
    $base = do_decrypt($base);

    if(empty($cookie) || empty($base)) exit_403();

    $redirectto = $cookie;
    if(strpos('?',$redirectto) !== false) {
        $redirectto .= "&";
    }
    else {
        $redirectto .= "?";
    }

    // append the parameters
    $redirectto.= "base=".b64_encode($base);
    $redirectto.= "&site=".b64_encode($site);
    if(!empty($action)) {
        $redirectto.= "&action=".$action; // no need to base64 encode this
    }
    if(!empty($cb)) {
        $redirectto .= "&cb=".b64_encode($cb);
    }
    header('Location: '.$redirectto);
}

function do_register($base,$site) {
    // check that site is a valid URL
    if(filter_var($site, FILTER_VALIDATE_URL, FILTER_FLAG_SCHEME_REQUIRED | FILTER_FLAG_HOST_REQUIRED) === false) {
        exit_403();
    }

    // base should be a valid absolute path, but it may or may not contain query parameters
    if($base[0] !== '/') exit_403();

    // a valid service should live at <base><site>
    $fullsite = $base . $site;
    if(!check_valid_service($fullsite)) exit_403();

    // encrypt the fullsite and base values
    $fullsite_enc = do_encrypt($fullsite);
    $base_enc = do_encrypt($base);

    // set the cookie containing the encoded base value
    setcookie($cookie_name, $fullsite_enc, time() + (3650*60*60*24), "/", $hostname, 1, true, Array("samesite"=>"None"));

    // return base and fullsite encoded values
    header($_SERVER['SERVER_PROTOCOL'] . ' 200 Ok', true, 200);
    echo json_encode(array("site"=>$fullsite_enc, "base"=>$base_enc));
}

function check_valid_service($fullsite) {
    if(strpos($fullsite,"?") !== false) {
        $fullsite .= "&";
    }
    else {
        $fullsite.="?";
    }
    $fullsite.="action=validate";
 
    $sess = curl_init();
    curl_setopt($sess, CURLOPT_HTTPGET,true);
    curl_setopt($sess, CURLOPT_RETURNTRANSFER,true);
    curl_setopt($sess, CURLOPT_FOLLOWLOCATION,true);
    curl_setopt($sess, CURLOPT_FORBID_REUSE,true);
    curl_setopt($sess, CURLOPT_FRESH_CONNECT,true);
    curl_setopt($sess, CURLOPT_SSL_VERIFYHOST, 2);
    curl_setopt($sess, CURLOPT_SSL_VERIFYPEER, true);
    curl_setopt($sess, CURLOPT_SSL_VERIFYSTATUS, false);
    curl_setopt($sess, CURLOPT_URL, $fullsite);
    $output=curl_exec($sess);
    $status = curl_getinfo($this->_session, CURLINFO_HTTP_CODE);

    return intval($status) === 200;
}

function do_decrypt($enc_text) {
    $tokens = explode(':',$enc_text);
    if(sizeof($tokens) != 2) return null;

    $iv_b64 = $tokens[0];
    $enc_b64 = $tokens[1];
    $iv=b64_decode($iv_b64);
    $enc=b64_decode($enc_b64);

    $plaintext = openssl_decrypt($enc, $cipher, $encryption_key, 0, $iv);
    if($plaintext === false) return null;

    return $plaintext;
}

function do_encrypt($plaintext) {
    $ivlength = openssl_cipher_iv_length($cipher);
    $iv = openssl_random_pseudo_bytes($ivlen);
    $enc = openssl_encrypt($plaintext, $cipher, $encryption_key, 0, $iv);

    $iv_b64 = base64_encode($iv);
    $enc_b64 = base64_encode($enc);
    $enc_text = $iv_b64 .":".$enc_b64;

    return $enc_text;
}

function exit_403() {
    header($_SERVER['SERVER_PROTOCOL'] . ' 403 Forbidden', true, 403);
    exit;
}

function b64_encode($val) {
    if(empty($val)) $val="";
    
    return "b64:".base64_encode($val);
}

function b64_decode($val) {
    if(!empty($val) && strpos($val,"b64:") === 0) {
        $val = base64_decode(substr($val,4));
    }
    return $val;
}