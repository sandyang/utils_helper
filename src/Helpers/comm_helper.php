<?php
if (! function_exists ( 'test_echo' )) {
    function test_echo() {
        echo 'test_echo';
    }
}


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
    function check_auth_token_for_vendor($token, &$error) {
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