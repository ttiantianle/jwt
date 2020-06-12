<?php
namespace app\common\components;

class Jwt
{
    private static $key = "asdioij";        //自行定义
    private static $string = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static $header = [ //header
      'alg' => 'sha256', //md5 或者 sha256等
      'typ' => 'JWT'
    ];

    /**
     * 生成token
     * @param array $payload
     * @return bool|string
     */
    public static function makeToken($payload = [])
    {
        if (!is_array($payload)) return false;
        $headerStr = self::base64UrlEncode(json_encode(self::$header));
        $payloadStr = self::base64UrlEncode(json_encode($payload));
        $alg= self::$header['alg'];
        $signatureStr = hash_hmac($alg,$headerStr.$payloadStr,self::$key);
        return $headerStr.'.'.$payloadStr.'.'.$signatureStr;
    }

    /**
     * 验证token
     * @param $token
     * @return bool|mixed
     */
    public static function verifyToken($token){

        if (!is_string($token)) return false;
        $arrToken = explode('.',$token);
        $tokenHeader = json_decode($arrToken[0]);
        $alg = $tokenHeader['alg'];
        if (!$alg) return false;
        $signatureStr = hash_hmac($alg,$arrToken[0].$arrToken[1],self::$key);
        if ($signatureStr != $arrToken[2])
        {
            return false;
        }
        $payload = json_decode(base64_decode($arrToken[1]));
        return $payload;
    }

    private static function base64UrlEncode($str)
    {
        return base64_encode($str);
    }

    private static function base64UrlDecode($base64Str){
        return base64_decode($base64Str);
    }
}