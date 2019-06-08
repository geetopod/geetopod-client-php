<?php
namespace geetoPod_Client;

class SSOClient {
    private $TIMEOUT = 1000 * 60 * 60;

    private $_clientId = '';
    private $_lastTime = 0;
    private $_expiresIn = 0;
    private $_token = "";
    private $_refreshToken = "";
    private $_refreshExpiresIn = 0;
    private $_online = false;
    private $_waitingOTP = false;
    private $_username = "";
    private $_password = "";
    private $_accessResources = array();
    private $_ssoInUse = false;
    private $_ssoToken = "";
    private $_company = "";

    public function company() {
        return $this->_company;
    }

    public function ssoInUse() {
        return $this->_ssoInUse;
    }

    public function ssoToken() {
        return $this->_ssoToken;
    }

    public function __construct($clientId = null) {
        if ($clientId != null) {
            $this->_clientId = $clientId;
        } else {
            if (isset($_SESSION['CLIENT_ID'])) {
                $this->clientId = $_SESSION['CLIENT_ID'];
            } else {
                $this->_clientId = uniqid();
            }
        }
        if (isset($_SESSION['CLIENT_ID']) && $_SESSION['CLIENT_ID'] == $this->_clientId) {
            if (isset($_SESSION['SSO_' . $this->_clientId . '_online'])) {
                $this->_lastTime = $_SESSION['SSO_' . $this->_clientId . '_lastTime'];
                $this->_expiresIn = $_SESSION['SSO_' . $this->_clientId . '_expiresIn'];
                $this->_token = $_SESSION['SSO_' . $this->_clientId . '_token'];
                $this->_refreshToken = $_SESSION['SSO_' . $this->_clientId . '_refreshToken'];
                $this->_refreshExpiresIn = $_SESSION['SSO_' . $this->_clientId . '_refreshExpiresIn'];
                $this->_online = $_SESSION['SSO_' . $this->_clientId . '_online'];
                $this->_waitingOTP = $_SESSION['SSO_' . $this->_clientId . '_waitingOTP'];
                $this->_username = $_SESSION['SSO_' . $this->_clientId . '_username'];
                $this->_password = $_SESSION['SSO_' . $this->_clientId . '_password'];
                $this->_accessResources = $_SESSION['SSO_' . $this->_clientId . '_accessResources'];
                $this->_ssoInUse = $_SESSION['SSO_' . $this->_clientId . '_ssoInUse'];
                $this->_ssoToken = $_SESSION['SSO_' . $this->_clientId . '_ssoToken'];
                $this->_company = $_SESSION['SSO_' . $this->_clientId . '_company'];
            } else {
                $_SESSION['CLIENT_ID'] = $this->_clientId;
                $_SESSION['SSO_' . $this->_clientId . '_lastTime'] = $this->_lastTime;
                $_SESSION['SSO_' . $this->_clientId . '_expiresIn'] = $this->_expiresIn;
                $_SESSION['SSO_' . $this->_clientId . '_token'] = $this->_token;
                $_SESSION['SSO_' . $this->_clientId . '_refreshToken'] = $this->_refreshToken;
                $_SESSION['SSO_' . $this->_clientId . '_refreshExpiresIn'] = $this->_refreshExpiresIn;
                $_SESSION['SSO_' . $this->_clientId . '_online'] = $this->_online;
                $_SESSION['SSO_' . $this->_clientId . '_waitingOTP'] = $this->_waitingOTP;
                $_SESSION['SSO_' . $this->_clientId . '_username'] = $this->_username;
                $_SESSION['SSO_' . $this->_clientId . '_password'] = $this->_password;
                $_SESSION['SSO_' . $this->_clientId . '_accessResources'] = $this->_accessResources;
                $_SESSION['SSO_' . $this->_clientId . '_ssoInUse'] = $this->_ssoInUse;
                $_SESSION['SSO_' . $this->_clientId . '_ssoToken'] = $this->_ssoToken;
                $_SESSION['SSO_' . $this->_clientId . '_company'] = $this->_company;
            }
        } else {
            $_SESSION['CLIENT_ID'] = $this->_clientId;
            $_SESSION['SSO_' . $this->_clientId . '_lastTime'] = $this->_lastTime;
            $_SESSION['SSO_' . $this->_clientId . '_expiresIn'] = $this->_expiresIn;
            $_SESSION['SSO_' . $this->_clientId . '_token'] = $this->_token;
            $_SESSION['SSO_' . $this->_clientId . '_refreshToken'] = $this->_refreshToken;
            $_SESSION['SSO_' . $this->_clientId . '_refreshExpiresIn'] = $this->_refreshExpiresIn;
            $_SESSION['SSO_' . $this->_clientId . '_online'] = $this->_online;
            $_SESSION['SSO_' . $this->_clientId . '_waitingOTP'] = $this->_waitingOTP;
            $_SESSION['SSO_' . $this->_clientId . '_username'] = $this->_username;
            $_SESSION['SSO_' . $this->_clientId . '_password'] = $this->_password;
            $_SESSION['SSO_' . $this->_clientId . '_accessResources'] = $this->_accessResources;
            $_SESSION['SSO_' . $this->_clientId . '_ssoInUse'] = $this->_ssoInUse;
            $_SESSION['SSO_' . $this->_clientId . '_ssoToken'] = $this->_ssoToken;
            $_SESSION['SSO_' . $this->_clientId . '_company'] = $this->_company;
        }
    }

    public function loginSSO($request) {
        $response = Services::instance()->validateSSOToken($request);
        $this->_ssoInUse = true;
        $this->_company = $request->company;
        if (!$response->isError && $response->active) {
            $this->_waitingOTP = false;
            $this->_online = true;
            $this->_lastTime = 0;
            $this->_expiresIn = 0;
            $this->_token = "";
            $this->_refreshToken = "";
            $this->_refreshExpiresIn = 0;

            $this->_username = "";
            $this->_password = "";
            $this->_accessResources = array();
            $this->_ssoToken = $request->ssoToken;
        } else {
            $this->_waitingOTP = false;
            $this->_online = false;
            $this->_lastTime = 0;
            $this->_expiresIn = 0;
            $this->_token = "";
            $this->_refreshToken = "";
            $this->_refreshExpiresIn = 0;
            $this->_ssoToken = "";
            $this->_ssoInUse = false;

            $this->_username = "";
            $this->_password = "";
            $this->_accessResources = array();
        }

        $_SESSION['SSO_' . $this->_clientId . '_lastTime'] = $this->_lastTime;
        $_SESSION['SSO_' . $this->_clientId . '_expiresIn'] = $this->_expiresIn;
        $_SESSION['SSO_' . $this->_clientId . '_token'] = $this->_token;
        $_SESSION['SSO_' . $this->_clientId . '_refreshToken'] = $this->_refreshToken;
        $_SESSION['SSO_' . $this->_clientId . '_refreshExpiresIn'] = $this->_refreshExpiresIn;
        $_SESSION['SSO_' . $this->_clientId . '_online'] = $this->_online;
        $_SESSION['SSO_' . $this->_clientId . '_waitingOTP'] = $this->_waitingOTP;
        $_SESSION['SSO_' . $this->_clientId . '_username'] = $this->_username;
        $_SESSION['SSO_' . $this->_clientId . '_password'] = $this->_password;
        $_SESSION['SSO_' . $this->_clientId . '_accessResources'] = $this->_accessResources;
        $_SESSION['SSO_' . $this->_clientId . '_ssoInUse'] = $this->_ssoInUse;
        $_SESSION['SSO_' . $this->_clientId . '_ssoToken'] = $this->_ssoToken;
        $_SESSION['SSO_' . $this->_clientId . '_company'] = $this->_company;

        return $response;
    }

    public function loginSocial($request) {
        $response = Services::instance()->socialLoginProcess($request);
        $this->_ssoInUse = false;
        $this->_company = $request->company;
        if ($response->isError) {
            $this->_waitingOTP = false;
            $this->_online = false;
            $this->_lastTime = 0;
            $this->_expiresIn = 0;
            $this->_token = "";
            $this->_refreshToken = "";
            $this->_refreshExpiresIn = 0;

            $this->_username = "";
            $this->_password = "";
            $this->_accessResources = array();
            $this->_ssoToken = "";
        } else {
            $this->_waitingOTP = false;
            $this->_online = true;
            $this->_lastTime = round(microtime(true) * 1000);
            $this->_expiresIn = $response->expiresIn;
            $this->_token = $response->token;
            $this->_refreshToken = $response->refreshToken;
            $this->_refreshExpiresIn = $response->refreshExpiresIn;
            $this->_ssoToken = $response->ssoToken;
            $this->_ssoInUse = false;

            $requestV = new ValidateTokenRequest();
            $requestV->company = $request->company;
            $requestV->token = $response->token;
            $responseV = Services::instance()->validateToken($requestV);

            $this->_username = $responseV->username;
            $this->_password = $request->verifiedToken;
            $this->_accessResources = array();
            for ($i = 0; $i < count($request->accessResources); $i++) {
                array_push($this->_accessResources, $request->accessResources[$i]);
            }
        }

        $_SESSION['SSO_' . $this->_clientId . '_lastTime'] = $this->_lastTime;
        $_SESSION['SSO_' . $this->_clientId . '_expiresIn'] = $this->_expiresIn;
        $_SESSION['SSO_' . $this->_clientId . '_token'] = $this->_token;
        $_SESSION['SSO_' . $this->_clientId . '_refreshToken'] = $this->_refreshToken;
        $_SESSION['SSO_' . $this->_clientId . '_refreshExpiresIn'] = $this->_refreshExpiresIn;
        $_SESSION['SSO_' . $this->_clientId . '_online'] = $this->_online;
        $_SESSION['SSO_' . $this->_clientId . '_waitingOTP'] = $this->_waitingOTP;
        $_SESSION['SSO_' . $this->_clientId . '_username'] = $this->_username;
        $_SESSION['SSO_' . $this->_clientId . '_password'] = $this->_password;
        $_SESSION['SSO_' . $this->_clientId . '_accessResources'] = $this->_accessResources;
        $_SESSION['SSO_' . $this->_clientId . '_ssoInUse'] = $this->_ssoInUse;
        $_SESSION['SSO_' . $this->_clientId . '_ssoToken'] = $this->_ssoToken;
        $_SESSION['SSO_' . $this->_clientId . '_company'] = $this->_company;

        return $response;
    }

    public function login($request) {
        $response = Services::instance()->login($request);
        $this->_ssoInUse = false;
        $this->_company = $request->company;
        if (!$response->isError) {
            $this->_lastTime = round(microtime(true) * 1000);
            $this->_expiresIn = $response->expiresIn;
            $this->_token = $response->token;
            $this->_refreshToken = $response->refreshToken;
            $this->_refreshExpiresIn = $response->refreshExpiresIn;
            $this->_online = true;
            $this->_ssoToken = $response->ssoToken;

            $this->_username = $request->username;
            $this->_password = $request->password;
            $this->_accessResources = array();
            for ($i = 0; $i < count($request->accessResources); $i++) {
                array_push($this->_accessResources, $request->accessResources[$i]);
            }

            if ($request->hasOTP) {
                $this->_waitingOTP = true;
                $this->_online = false;
            } else {
                $this->_waitingOTP = false;
            }
        } else {
            $this->_waitingOTP = false;
            $this->_online = false;
            $this->_lastTime = 0;
            $this->_expiresIn = 0;
            $this->_token = "";
            $this->_refreshToken = "";
            $this->_refreshExpiresIn = 0;
            $this->_ssoToken = "";

            $this->_username = "";
            $this->_password = "";
            $this->_accessResources = array();
        }

        $_SESSION['SSO_' . $this->_clientId . '_lastTime'] = $this->_lastTime;
        $_SESSION['SSO_' . $this->_clientId . '_expiresIn'] = $this->_expiresIn;
        $_SESSION['SSO_' . $this->_clientId . '_token'] = $this->_token;
        $_SESSION['SSO_' . $this->_clientId . '_refreshToken'] = $this->_refreshToken;
        $_SESSION['SSO_' . $this->_clientId . '_refreshExpiresIn'] = $this->_refreshExpiresIn;
        $_SESSION['SSO_' . $this->_clientId . '_online'] = $this->_online;
        $_SESSION['SSO_' . $this->_clientId . '_waitingOTP'] = $this->_waitingOTP;
        $_SESSION['SSO_' . $this->_clientId . '_username'] = $this->_username;
        $_SESSION['SSO_' . $this->_clientId . '_password'] = $this->_password;
        $_SESSION['SSO_' . $this->_clientId . '_accessResources'] = $this->_accessResources;
        $_SESSION['SSO_' . $this->_clientId . '_ssoInUse'] = $this->_ssoInUse;
        $_SESSION['SSO_' . $this->_clientId . '_ssoToken'] = $this->_ssoToken;
        $_SESSION['SSO_' . $this->_clientId . '_company'] = $this->_company;

        return $response;
    }

    public function loginOTP($request) {
        $this->_ssoInUse = false;
        $this->_company = $request->company;
        $response = Services::instance()->loginOTP($request);
        if (!$response->isError) {
            $this->_lastTime = round(microtime(true) * 1000);
            $this->_expiresIn = $response->expiresIn;
            $this->_token = $response->token;
            $this->_refreshToken = $response->refreshToken;
            $this->_refreshExpiresIn = $response->refreshExpiresIn;
            $this->_online = true;
            $this->_waitingOTP = true;
            $this->_ssoToken = $response->ssoToken;
        } else {
            $this->_waitingOTP = false;
            $this->_online = false;
            $this->_lastTime = 0;
            $this->_expiresIn = 0;
            $this->_token = "";
            $this->_refreshToken = "";
            $this->_refreshExpiresIn = 0;
            $this->_ssoToken = "";

            $this->_username = "";
            $this->_password = "";
            $this->_accessResources = array();
        }

        $_SESSION['SSO_' . $this->_clientId . '_lastTime'] = $this->_lastTime;
        $_SESSION['SSO_' . $this->_clientId . '_expiresIn'] = $this->_expiresIn;
        $_SESSION['SSO_' . $this->_clientId . '_token'] = $this->_token;
        $_SESSION['SSO_' . $this->_clientId . '_refreshToken'] = $this->_refreshToken;
        $_SESSION['SSO_' . $this->_clientId . '_refreshExpiresIn'] = $this->_refreshExpiresIn;
        $_SESSION['SSO_' . $this->_clientId . '_online'] = $this->_online;
        $_SESSION['SSO_' . $this->_clientId . '_waitingOTP'] = $this->_waitingOTP;
        $_SESSION['SSO_' . $this->_clientId . '_username'] = $this->_username;
        $_SESSION['SSO_' . $this->_clientId . '_password'] = $this->_password;
        $_SESSION['SSO_' . $this->_clientId . '_accessResources'] = $this->_accessResources;
        $_SESSION['SSO_' . $this->_clientId . '_ssoInUse'] = $this->_ssoInUse;
        $_SESSION['SSO_' . $this->_clientId . '_ssoToken'] = $this->_ssoToken;
        $_SESSION['SSO_' . $this->_clientId . '_company'] = $this->_company;

        return $response;
    }

    public function waitingOTP() {
        return $this->_waitingOTP;
    }

    public function online() {
        try {
            if ($this->_ssoInUse) {
                $request = new ValidateSSOTokenRequest();
                $request->company = $this->_company;
                $request->ssoToken = $this->_ssoToken;
                $this->loginSSO($request);
            } else {
                $this->token();
            }
            return $this->_online;
        } catch (\Exception $e) {
            return false;
        }
    }

    public function logout($allClients) {
        $response = new LogoutResponse();
        if ($allClients) {
            $request = new LogoutRequest();
            $request->company = $this->_company;
            $request->token = $this->_token;
            $response = Services::instance()->logout($request);
            if ($response->isError) {
                return $response;
            }
        }
        $this->_online = false;
        $this->_waitingOTP = false;
        $this->_lastTime = 0;
        $this->_expiresIn = 0;
        $this->_token = "";
        $this->_refreshToken = "";
        $this->_refreshExpiresIn = 0;
        $this->_username = "";
        $this->_password = "";
        $this->_accessResources = array();
        $this->_company = "";
        $this->_ssoToken = '';
        $this->_ssoInUse = false;

        $_SESSION['SSO_' . $this->_clientId . '_lastTime'] = $this->_lastTime;
        $_SESSION['SSO_' . $this->_clientId . '_expiresIn'] = $this->_expiresIn;
        $_SESSION['SSO_' . $this->_clientId . '_token'] = $this->_token;
        $_SESSION['SSO_' . $this->_clientId . '_refreshToken'] = $this->_refreshToken;
        $_SESSION['SSO_' . $this->_clientId . '_refreshExpiresIn'] = $this->_refreshExpiresIn;
        $_SESSION['SSO_' . $this->_clientId . '_online'] = $this->_online;
        $_SESSION['SSO_' . $this->_clientId . '_waitingOTP'] = $this->_waitingOTP;
        $_SESSION['SSO_' . $this->_clientId . '_username'] = $this->_username;
        $_SESSION['SSO_' . $this->_clientId . '_password'] = $this->_password;
        $_SESSION['SSO_' . $this->_clientId . '_accessResources'] = $this->_accessResources;
        $_SESSION['SSO_' . $this->_clientId . '_ssoToken'] = $this->_ssoToken;
        $_SESSION['SSO_' . $this->_clientId . '_ssoInUse'] = $this->_ssoInUse;
        $_SESSION['SSO_' . $this->_clientId . '_company'] = $this->_company;

        return $response;
    }

    public function token() {
        if ($this->_ssoInUse) {
            throw new \Exception('Single sign on is in use!');
            return false;
        }
        if ($this->_token == null || strlen($this->_token) == 0) {
            throw new \Exception('Client is not online!');
            return false;
        }
        if ($this->_lastTime == 0 || $this->_lastTime < round(microtime(true) * 1000) - $this->_expiresIn * 1000) {
            if ($this->_lastTime == 0 || ($this->_lastTime < round(microtime(true) * 1000) - ($this->_refreshExpiresIn - 5) * 1000)) {
                $loginRequest = new LoginRequest();
                $loginRequest->company = $this->_company;
                $loginRequest->username = $this->_username;
                $loginRequest->password = $this->_password;
                for ($i = 0; $i < count($this->_accessResources); $i++) {
                    array_push($loginRequest->accessResources, $this->_accessResources[$i]);
                }
                $loginResponse = $this->login($loginRequest);
                if ($loginResponse->isError) {
                    throw new \Exception('[' . $loginResponse->errorCode . '] ' . $loginResponse->errorMessage);
                    return false;
                } else {
                    return $this->_token;
                }
            } else {
                $refreshTokenRequest = new RefreshTokenRequest();
                $refreshTokenRequest->company = $this->_company;
                $refreshTokenRequest->refreshToken = $this->_refreshToken;
                $refreshTokenResponse = Services::instance()->refreshToken($refreshTokenRequest);
                if ($refreshTokenResponse->isError) {
                    throw new \Exception('[' . $refreshTokenResponse->errorCode . '] ' . $refreshTokenResponse->errorMessage);
                    return false;
                } else {
                    $this->_lastTime = round(microtime(true) * 1000);
                    $this->_expiresIn = $refreshTokenResponse->expiresIn;
                    $this->_token = $refreshTokenResponse->token;
                    $this->_refreshToken = $refreshTokenResponse->refreshToken;
                    $this->_refreshExpiresIn = $refreshTokenResponse->refreshExpiresIn;
                    $this->_online = true;
                    $this->_waitingOTP = false;

                    $_SESSION['SSO_' . $this->_clientId . '_lastTime'] = $this->_lastTime;
                    $_SESSION['SSO_' . $this->_clientId . '_expiresIn'] = $this->_expiresIn;
                    $_SESSION['SSO_' . $this->_clientId . '_token'] = $this->_token;
                    $_SESSION['SSO_' . $this->_clientId . '_refreshToken'] = $this->_refreshToken;
                    $_SESSION['SSO_' . $this->_clientId . '_refreshExpiresIn'] = $this->_refreshExpiresIn;
                    $_SESSION['SSO_' . $this->_clientId . '_online'] = $this->_online;
                    $_SESSION['SSO_' . $this->_clientId . '_waitingOTP'] = $this->_waitingOTP;
                    $_SESSION['SSO_' . $this->_clientId . '_username'] = $this->_username;
                    $_SESSION['SSO_' . $this->_clientId . '_password'] = $this->_password;
                    $_SESSION['SSO_' . $this->_clientId . '_accessResources'] = $this->_accessResources;
                    $_SESSION['SSO_' . $this->_clientId . '_company'] = $this->_company;

                    return $this->_token;
                }
            }
        } else {
            return $this->_token;
        }
    }
}

class Clients {
    private static $__instance;
    private $_clientMap = array();

    public static function instance() {
        if (!isset(self::$__instance)) {
            self::$__instance = new Clients();
        }
        return self::$__instance;
    }

    public function getClient($code = null) {
        if ($code == null || $code == false) {
            if (isset($_SESSION['CLIENT_ID'])) {
                $code = $_SESSION['CLIENT_ID'];
            } else {
                $code = uniqid();
                $_SESSION['CLIENT_ID'] = $code;
            }
            return $this->getClient($code);
        }
        if (array_key_exists($code, $this->_clientMap)) {
            return $this->_clientMap[$code];
        }
        $client = new SSOClient($code);
        $this->_clientMap[$code] = $client;
        return $client;
    }
}

class Services {
    private static $__instance;
    private $_gatewayUrl;

    public static function instance() {
        if (!isset(self::$__instance)) {
            self::$__instance = new Services();
        }
        return self::$__instance;
    }

    public function getGatewayUrl() {
        return $this->_gatewayUrl;
    }

    public function setGatewayUrl($url) {
        $index = strpos($url, '/', strlen('https://'));
        if ($index !== false) {
            $url = substr($url, 0, $index);
        }
        $this->_gatewayUrl = $url;
    }

    public function post($url, $inputJson) {
        $ch = curl_init();

        curl_setopt($ch, CURLOPT_URL, $this->getGatewayUrl() . $url);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "POST");
        curl_setopt($ch, CURLOPT_POSTFIELDS, $inputJson);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array(
            'Content-Type: application/json',
            'Content-Length: ' . strlen($inputJson))
        );

        $responseJson = curl_exec($ch);

        curl_close($ch);

        return $responseJson;
    }

    public function callApi($url, &$request, &$response) {
        $requestJson = json_encode($request);
        $responseJson = $this->post($url, $requestJson);
        $data = json_decode($responseJson, true);
        foreach ($data as $key => $value) $response->{$key} = $value;
    }

    public function changePassword($request) {
        $response = new ChangePasswordResponse();
        $this->callApi('/api/password/change', $request, $response);
        return $response;
    }

    public function forgotPasswordSendByEmail($request) {
        $response = new ForgotPasswordSendByEmailResponse();
        $this->callApi('/api/forgot/password/sendby/email', $request, $response);
        return $response;
    }

    public function forgotPasswordSendByPhone($request) {
        $response = new ForgotPasswordSendByPhoneResponse();
        $this->callApi('/api/forgot/password/sendby/phone', $request, $response);
        return $response;
    }

    public function forgotPassword($request) {
        $response = new ForgotPasswordResponse();
        $this->callApi('/api/forgot/password', $request, $response);
        return $response;
    }

    public function getSSOTokenUrl($request) {
        $response = new GetSSOTokenUrlResponse();
        $this->callApi('/api/ssotoken/url/get', $request, $response);
        return $response;
    }

    public function putSSOTokenUrl($request) {
        $response = new PutSSOTokenUrlResponse();
        $this->callApi('/api/ssotoken/url/put', $request, $response);
        return $response;
    }


    public function socialLoginUrl($request) {
        $response = new SocialLoginUrlResponse();
        $this->callApi('/api/social/login/url', $request, $response);
        return $response;
    }

    public function socialLoginProcess($request) {
        $response = new SocialLoginProcessResponse();
        $this->callApi('/api/social/login/process', $request, $response);
        return $response;
    }


    public function createResource($request) {
        $response = new CreateResourceResponse();
        $this->callApi('/api/resource/create', $request, $response);
        return $response;
    }

    public function listResource($request) {
        $response = new ListResourceResponse();
        $this->callApi('/api/resource/list', $request, $response);
        return $response;
    }

    public function deleteResource($request) {
        $response = new DeleteResourceResponse();
        $this->callApi('/api/resource/delete', $request, $response);
        return $response;
    }

    public function assignResource($request) {
        $response = new AssignResourceResponse();
        $this->callApi('/api/resource/assign', $request, $response);
        return $response;
    }

    public function unassignResource($request) {
        $response = new UnassignResourceResponse();
        $this->callApi('/api/resource/unassign', $request, $response);
        return $response;
    }


    public function getUserInfo($request) {
        $response = new GetUserInfoResponse();
        $this->callApi('/api/userinfo', $request, $response);
        return $response;
    }

    public function loginByPhone($request) {
        $response = new LoginByPhoneResponse();
        $this->callApi('/api/login/byphone', $request, $response);
        return $response;
    }

    public function login($request) {
        $response = new LoginResponse();
        $this->callApi('/api/login', $request, $response);
        return $response;
    }

    public function loginOTP($request) {
        $response = new LoginOTPResponse();
        $this->callApi('/api/login/otp', $request, $response);
        return $response;
    }

    public function logout($request) {
        $response = new LogoutResponse();
        $this->callApi('/api/logout', $request, $response);
        return $response;
    }

    public function refreshToken($request) {
        $response = new RefreshTokenResponse();
        $this->callApi('/api/token/refresh', $request, $response);
        return $response;
    }

    public function registerByPhone($request) {
        $response = new RegisterByPhoneResponse();
        $this->callApi('/api/register/byphone', $request, $response);
        return $response;
    }

    public function registerCaptcha($request) {
        $response = new RegisterCaptchaResponse();
        $this->callApi('/api/register/captcha', $request, $response);
        return $response;
    }

    public function registerResendVerifyEmail($request) {
        $response = new RegisterResendVerifyEmailResponse();
        $this->callApi('/api/register/resend/verify/email', $request, $response);
        return $response;
    }

    public function registerSendVerifyPhone($request) {
        $response = new RegisterSendVerifyPhoneResponse();
        $this->callApi('/api/register/send/verify/phone', $request, $response);
        return $response;
    }

    public function registerCompany($request) {
        $response = new RegisterCompanyResponse();
        $this->callApi('/api/register/company', $request, $response);
        return $response;
    }

    public function register($request) {
        $response = new RegisterResponse();
        $this->callApi('/api/register', $request, $response);
        return $response;
    }

    public function registerVerifyEmail($request) {
        $response = new RegisterVerifyEmailResponse();
        $this->callApi('/api/register/verify/email', $request, $response);
        return $response;
    }

    public function registerVerifyPhone($request) {
        $response = new RegisterVerifyPhoneResponse();
        $this->callApi('/api/register/verify/phone', $request, $response);
        return $response;
    }

    public function updateUserInfo($request) {
        $response = new UpdateUserInfoResponse();
        $this->callApi('/api/userinfo/update', $request, $response);
        return $response;
    }

    public function validateToken($request) {
        $response = new ValidateTokenResponse();
        $this->callApi('/api/token/validate', $request, $response);
        return $response;
    }

    public function validateSSOToken($request) {
        $response = new ValidateSSOTokenResponse();
        $this->callApi('/api/ssotoken/validate', $request, $response);
        return $response;
    }
}

class BasicRequest {

}

class AuthorizedRequest extends BasicRequest {
    public $company = "";
    public $token = "";
    public $ssoToken = "";
}

class BasicResponse {
    public $isError = false;
    public $errorCode = "";
    public $errorMessage = "";
}


class AssignResourceRequest extends AuthorizedRequest {
    public $resource = "";
    public $username = "";
}

class AssignResourceResponse extends BasicResponse {
}

class CreateResourceRequest extends AuthorizedRequest {
    public $resource = "";
}

class CreateResourceResponse extends BasicResponse {
}

class DeleteResourceRequest extends AuthorizedRequest {
    public $resource = "";
}

class DeleteResourceResponse extends BasicResponse {
}

class ListResourceRequest extends AuthorizedRequest {
    public $usernames = array();
}

class ListResourceResponse extends BasicResponse {
    public $resources = array();
    public $assignedResources = array();
}

class UnassignResourceRequest extends AuthorizedRequest {
    public $resource = "";
    public $username = "";
}

class UnassignResourceResponse extends BasicResponse {
}

class ChangePasswordRequest extends AuthorizedRequest {
    public $password = "";
}

class ChangePasswordResponse extends BasicResponse {
}

class ForgotPasswordRequest extends BasicRequest {
    public $company = "";
    public $phone = "";
    public $token = "";
    public $password = "";
}

class ForgotPasswordResponse extends BasicResponse {
}

class ForgotPasswordSendByEmailRequest extends BasicRequest {
    public $company = "";
    public $email = "";
    public $subjectTemplate = "";
    public $bodyTextTemplate = "";
    public $bodyHtmlTemplate = "";
}

class ForgotPasswordSendByEmailResponse extends BasicResponse {
}

class ForgotPasswordSendByPhoneRequest extends BasicRequest {
    public $company = "";
    public $phone = "";
    public $bodyTextTemplate = "";
}

class ForgotPasswordSendByPhoneResponse extends BasicResponse {
}

class GetSSOTokenUrlRequest extends BasicRequest {
    public $company = "";
    public $redirectUrl = "";
}

class GetSSOTokenUrlResponse extends BasicResponse {
    public $url = "";
}

class GetUserInfoRequest extends AuthorizedRequest {
}

class GetUserInfoResponse extends BasicResponse {
    public $company = "";
    public $username = "";
    public $email = "";
    public $emailVerified = false;
    public $firstName = "";
    public $lastName = "";
    public $middleName = "";
    public $phone = "";
    public $phoneVerified = false;
    public $mailingAddress = "";
    public $billingAddress = "";
    public $country = "";
    public $state = "";
    public $postalCode = "";
}

class LoginByPhoneRequest extends BasicRequest {
    public $company = "";
    public $phone = "";
    public $verifiedToken = "";
    public $accessResources = array();
}

class LoginByPhoneResponse extends BasicResponse {
    public $token = "";
    public $refreshToken = "";
    public $expiresIn = 0;
    public $refreshExpiresIn = 0;
    public $permissions = array();
}

class LoginRequest extends BasicRequest {
    public $company = "";
    public $username = "";
    public $password = "";
    public $accessResources = array();
    public $hasOTP = false;
    public $hasSSO = false;
    public $bodyTextTemplate = "";
}

class LoginResponse extends BasicResponse {
    public $ssoToken = "";
    public $token = "";
    public $refreshToken = "";
    public $expiresIn = 0;
    public $refreshExpiresIn = 0;
    public $permissions = array();
    public $phone = "";
}

class LoginOTPRequest extends BasicRequest {
    public $company = "";
    public $phone = "";
    public $token = "";
}

class LoginOTPResponse extends BasicResponse {
    public $ssoToken = "";
    public $token = "";
    public $refreshToken = "";
    public $expiresIn = 0;
    public $refreshExpiresIn = 0;
    public $permissions = array();
}

class LogoutRequest extends AuthorizedRequest {

}

class LogoutResponse extends BasicResponse {

}

class Permission {
    public $code = "";
    public $name = "";
    public $token = "";
    public $refereshToken = "";
    public $expiresIn = 0;
    public $refreshExpiresIn = 0;
}

class PutSSOTokenUrlRequest extends BasicRequest {
    public $company = "";
    public $redirectUrl = "";
    public $ssoToken = "";
}

class PutSSOTokenUrlResponse extends BasicResponse {
    public $url = "";
}

class RefreshTokenRequest extends BasicRequest {
    public $company = "";
    public $refreshToken = "";
}

class RefreshTokenResponse extends BasicResponse {
    public $token = "";
    public $refreshToken = "";
    public $expiresIn = 0;
    public $refreshExpiresIn = 0;
}

class RegisterByPhoneRequest extends BasicRequest {
    public $company = "";
    public $phone = "";
    public $verifiedToken = "";
}

class RegisterByPhoneResponse extends BasicResponse {
    public $token = "";
    public $refreshToken = "";
    public $expiresIn = 0;
    public $refreshExpiresIn = 0;
}

class RegisterCaptchaRequest extends BasicRequest {
    public $company = "";
}

class RegisterCaptchaResponse extends BasicResponse {
    public $captchaCode = "";
    public $captchaImageUrl = "";
}

class RegisterCompanyRequest extends BasicRequest {
    public $companyCode = "";
    public $companyName = "";

    public $adminUsername = "";
    public $adminPassword = "";
    public $adminEmail = "";
    public $adminFirstName = "";
    public $adminLastName = "";
    public $adminMiddleName = "";
    public $adminPhone = "";
    public $adminMailingAddress = "";
    public $adminBillingAddress = "";
    public $adminCountry = "";
    public $adminState = "";
    public $adminPostalCode = "";

    public $captchaCode = "";
    public $captchaText = "";

    public $verifyEmailSubjectTemplate = "";
    public $verifyEmailBodyTextTemplate = "";
    public $verifyEmailBodyHtmlTemplate = "";
}

class RegisterCompanyResponse extends BasicResponse {
}

class RegisterRequest extends BasicRequest {
    public $company = "";
    public $username = "";
    public $password = "";
    public $email = "";
    public $firstName = "";
    public $lastName = "";
    public $middleName = "";
    public $phone = "";
    public $mailingAddress = "";
    public $billingAddress = "";
    public $country = "";
    public $state = "";
    public $postalCode = "";

    public $captchaCode = "";
    public $captchaText = "";

    public $verifyEmailSubjectTemplate = "";
    public $verifyEmailBodyTextTemplate = "";
    public $verifyEmailBodyHtmlTemplate = "";
}

class RegisterResponse extends BasicResponse {
    public $token = "";
    public $refreshToken = "";
    public $expiresIn = 0;
    public $refreshExpiresIn = 0;
}

class RegisterResendVerifyEmailRequest extends AuthorizedRequest {
    public $subjectTemplate = "";
    public $bodyTextTemplate = "";
    public $bodyHtmlTemplate = "";
}

class RegisterResendVerifyEmailResponse extends BasicResponse {

}

class RegisterSendVerifyPhoneRequest extends BasicRequest {
    public $company = "";
    public $token = "";
    public $phone = "";
    public $bodyTextTemplate = "";
}

class RegisterSendVerifyPhoneResponse extends BasicResponse {

}

class RegisterVerifyEmailRequest extends BasicRequest {
    public $company = "";
    public $verifyToken = "";
}

class RegisterVerifyEmailResponse extends BasicResponse {
    public $verifiedToken = "";
}

class RegisterVerifyPhoneRequest extends BasicRequest {
    public $company = "";
    public $phone = "";
    public $verifyToken = "";
}

class RegisterVerifyPhoneResponse extends BasicResponse {
    public $verifiedToken = "";
}

class SocialLoginProcessRequest extends BasicRequest {
    public $company = "";
    public $verifiedToken = "";
    public $hasSSO = false;
    public $accessResources = array();
}

class SocialLoginProcessResponse extends BasicResponse {
    public $ssoToken = "";
    public $token = "";
    public $refreshToken = "";
    public $expiresIn = 0;
    public $refreshExpiresIn = 0;
    public $permissions = array();
}

class SocialLoginUrlRequest extends BasicRequest {
    public $company = "";
    public $provider = "";
    public $redirectUrl = "";
}

class SocialLoginUrlResponse extends BasicResponse {
    public $url = "";
}

class UpdateUserInfoRequest extends AuthorizedRequest {
    public $username = "";
    public $email = "";
    public $firstName = "";
    public $lastName = "";
    public $middleName = "";
    public $phone = "";
    public $mailingAddress = "";
    public $billingAddress = "";
    public $country = "";
    public $state = "";
    public $postalCode = "";
}

class UpdateUserInfoResponse extends BasicResponse {

}

class ValidateTokenRequest extends AuthorizedRequest {

}

class ValidateTokenResponse extends BasicResponse {
    public $company = "";
    public $active = false;
    public $username = "";
    public $preferredUsername = "";
    public $email = "";
    public $emailVerified = false;
    public $firstName = "";
    public $lastName = "";
    public $fullName = "";
    public $permissions = array();
}

class ValidateSSOTokenRequest extends AuthorizedRequest {
    public $accessResources = array();
}

class ValidateSSOTokenResponse extends BasicResponse {
    public $company = "";
    public $active = false;
    public $username = "";
    public $firstName = "";
    public $lastName = "";
    public $permissions = array();
}

?>