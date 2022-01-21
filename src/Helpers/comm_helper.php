<?php

use CodeIgniter\I18n\Time;

if (! function_exists ( 'check_auth_token' )) {
    /**
     * 校验token的有效性并且解析后的token包含的数据
     *
     * @param string $token
     * @param string $error
     *        	解析或者校验的具体错误信息
     *
     * @return array The claim set of the token
     */
    function check_auth_token($token, &$error) {
        require_once APPPATH . '../vendor/autoload.php';
        $matches = [ ];
        if (preg_match ( '/Bearer\s(\S+)/', $token, $matches )) {
            $token = $matches [1];
        }
        // parse the token
        $parser = new Lcobucci\JWT\Parser ();
        try {
            $token = $parser->parse ( $token );
        } catch ( Exception $e ) {
            $error = $e->getMessage ();
            return false;
        }
        $config = new \Config\Environment ();
        $public_key_path = $config->jwtPublicKeyPath;
        if (! $public_key_path) {
            $error = 'signer key unconfiged';
            return false;
        }
        if (! file_exists ( $public_key_path )) {
            $error = 'public key file is not exist.' . $public_key_path;
            return false;
        }

        // validate the token
        $validator = new Lcobucci\JWT\Validation\Validator ();
        $result = $validator->validate ( $token, new Lcobucci\JWT\Validation\Constraint\SignedWith ( new Lcobucci\JWT\Signer\Rsa\Sha256 (), Lcobucci\JWT\Signer\Key\LocalFileReference::file ( $public_key_path ) ) );
        if (! $result) {
            $error = 'Invalid Token';
            return false;
        }
        if ($token->isExpired ( new DateTimeImmutable () )) {
            $error = 'Token Expired';
            return false;
        }

        return $token->claims ()->all ();
    }
}

if (! function_exists ( 'get_user_id' )) {
    /**
     * 从请求的Header里面获取Authorization Token，并解析返回对应的User ID
     *
     * @return int The user ID or false
     */
    function get_user_id() {
        $request = service ( 'request' );
        $token = $request->getHeaderLine ( 'Authorization' );
        if ($token) {
            $result = check_auth_token ( $token, $error );
            if ($result) {
                return $result ['user_id'];
            }
        }
        return false;
    }
}

if (! function_exists ( 'get_meta_codes_array' )) {
    function get_meta_codes_array($type_id, $all_fields = false) {
        $metaCodeModel = new \Merch\Models\MetaCodeModel ();
        $codes = $metaCodeModel->where ( 'type_id', $type_id )->orderBy ( 'pos' )->findAll ();

        if ($all_fields) {
            return $codes;
        }

        $code_array = array ();
        $value_key = 'value_en';
        foreach ( $codes as $code ) {
            $code_array [$code ['key']] = $code [$value_key];
        }
        return $code_array;
    }
}

if (! function_exists ( 'get_meta_code_value_by_key' )) {
    function get_meta_code_value_by_key($type_id, $key) {
        $metaCodeModel = new \Merch\Models\MetaCodeModel ();
        $code = $metaCodeModel->where ( 'type_id', $type_id )->where ( 'key', $key )->orderBy ( 'pos' )->first ();
        return $code ? $code ['value_en'] : '';
    }
}

if (! function_exists ( 'is_authorized' )) {
    function is_authorized($privilege_key, $platform_key='vendor') {
        $params = [
            'platform_key' => $platform_key,
            'operation_key' => $privilege_key
        ];
        $apiGateway = service ( 'apigateway' );
        $response = $apiGateway->call ( 'hub/auth/user/operation/check', $params );
        return $response ['result'] && $response ['object'];
    }
}

if (! function_exists ( 'curl_synchronous_call' )) {
    function curl_synchronous_call($method, $url, $params = array(), $headers = array()) {
        $client = \Config\Services::curlrequest ();
        $options = array ();

        if (! isset ( $headers ['User-Agent'] )) {
            $headers ['User-Agent'] = CURL_WEEE_AGENT;
        }
        if ($method === 'POST' && ! isset ( $headers ['Content-Type'] )) {
            // 默认是json格式
            $headers ['Content-Type'] = 'application/json';
        }
        $options ['headers'] = $headers;

        $body = '';
        if ($params) {
            if ($method === 'GET') {
                $url .= '?' . http_build_query ( $params );
            } else if ($method === 'POST') {
                if ($headers ['Content-Type'] === 'application/x-www-form-urlencoded') {
                    $options ['form_params'] = $params;
                } else {
                    $body = json_encode ( $params );
                }
            }
        }
        $client->setBody ( $body );
        // $options ['debug'] = true;
        $response = $client->request ( $method, $url, $options );
        $body = $response->getBody ();
        // json返回，解析成数组结构
        if (strpos ( $response->getHeader ( 'content-type' ), 'application/json' ) !== false) {
            $body = json_decode ( $body, true );
        }
        return $body;
    }
}

if (! function_exists ( 'send_email' )) {
    function send_email($to, $subject, $email_body, $source_code = 'Merch') {
        if (is_string ( $to )) {
            $to = explode ( ',', $to );
        }
        $params [] = [
            'body' => $email_body,
            'subject' => $subject,
            'to_list' => $to,
            'source_code' => $source_code
        ];
        $apiGateway = service ( 'apigateway' );
        $response = $apiGateway->call ( 'message/email/', $params, [], 'POST', true );
        if (! $response ['result']) {
            log_message ( 'error', 'Failed to call email API. ' . $response ['message'] );
        }
        return $response ['result'];
    }
}

if (! function_exists ( 'gen_uuid' )) {
    function gen_uuid() {
        return sprintf ( '%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
            // 32 bits for "time_low"
            mt_rand ( 0, 0xffff ), mt_rand ( 0, 0xffff ),

            // 16 bits for "time_mid"
            mt_rand ( 0, 0xffff ),

            // 16 bits for "time_hi_and_version",
            // four most significant bits holds version number 4
            mt_rand ( 0, 0x0fff ) | 0x4000,

            // 16 bits, 8 bits for "clk_seq_hi_res",
            // 8 bits for "clk_seq_low",
            // two most significant bits holds zero and one for variant DCE1.1
            mt_rand ( 0, 0x3fff ) | 0x8000,

            // 48 bits for "node"
            mt_rand ( 0, 0xffff ), mt_rand ( 0, 0xffff ), mt_rand ( 0, 0xffff ) );
    }
}
if (! function_exists ( 'get_config_value' )) {
    function get_config_value($key, $need_extra_values = false)
    {
        $data = (new \Merch\Models\Comm\ConfigModel())->where(['key' => $key])->get()->getRowArray();

        if ($data) {
            if ($need_extra_values) {
                return $data;
            } else {
                return $data ['value'];
            }
        } else {
            return false;
        }
    }
}
if (! function_exists ( 'get_local_time_str' )) {
    function get_local_time_str($time, $timezone, $format = 'Y-m-d H:i:s T') {
        return ( new DateTime ( '', new DateTimeZone ( $timezone ) ) )->setTimestamp ( strtotime ( $time ) )->format ( $format );
    }
}