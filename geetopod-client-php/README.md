![geetoPod - Identiy Solutions](https://github.com/geetopod/geetopod/raw/master/resources/images/geetopod-banner-96.png)

# PHP Client

## How to use

### 1. Include ssopod-client.php

```
require_once('geetopod-client.php');
```

### 2. Set gateway url

```
global $g_config;

\geetoPod_Client\Services::instance()->setGatewayUrl($g_config['gateway.url']);
```

### 3. Get services object

```
$services = \geetoPod_Client\Services::instance();
```

### 4. Get client object

```
$client = \geetoPod_Client\Clients::instance()->getClient(null);
```

### 5. Login (no OTP, no SSO)

```
global $g_config;

$client = \geetoPod_Client\Clients::instance()->getClient(null);

$username = g_param('username');
$password = g_param('password');
$request = new \geetoPod_Client\LoginRequest();
$request->company = $g_config['company'];
$request->username = $username;
$request->password = $password;
$request->hasSSO = false;
$request->hasOTP = false;
$response = $client->login($request);
if ($response->isError) {
    $message = $response->errorMessage;
} else {
    header('Location: /u/profile');
    exit();
}
```

### 6. Logout

```
$clearAllSessions = false;

$client = \geetoPod_Client\Clients::instance()->getClient(null);

$response = $client->logout($clearAllSessions);
```

### 8. Login (has OTP, no SSO)

```
global $g_config;

$client = \geetoPod_Client\Clients::instance()->getClient(null);

$username = g_param('username');
$password = g_param('password');
$request = new \SSO_Pod_Client\LoginRequest();
$request->company = $g_config['company'];
$request->username = $username;
$request->password = $password;
$request->hasSSO = false;
$request->hasOTP = true;
$response = $client->login($request);
if ($response->isError) {
    $message = $response->errorMessage;
} else if (strlen($response->token) == 0) {
    $OTPToken = g_param('OTPToken');
    $phone = $response->phone;
    $request = new \SSO_Pod_Client\LoginOTPRequest();
    $request->company = $g_config['company'];
    $request->phone = $phone;
    $request->token = $OTPToken;
    $response = $client->loginOTP($request);
    if ($response->isError) {
       $message = $response->errorMessage;
    }
}
```

### 8. Login (no OTP, has SSO)

```
global $g_config, $g_uri;

if ($g_uri == '/login') {
    $client = \geetoPod_Client\Clients::instance()->getClient(null);
    $services = \geetoPod_Client\Services::instance();

    $username = g_param('username');
    $password = g_param('password');
    $request = new \SSO_Pod_Client\LoginRequest();
    $request->company = $g_config['company'];
    $request->username = $username;
    $request->password = $password;
    $request->hasSSO = true;
    $request->hasOTP = false;
    $response = $client->login($request);
    if ($response->isError) {
         $message = $response->errorMessage;
    } else {
         $ssoToken = $response->ssoToken;
        if (strlen($ssoToken) > 0) {
            $requestU = new \SSO_Pod_Client\PutSSOTokenUrlRequest();
            $requestU->ssoToken = $ssoToken;
            $requestU->company = $g_config['company'];
            $requestU->redirectUrl = $g_config['web.url'] . "/postlogin";
            $responseU = $services->putSSOTokenUrl($requestU);
            $goUrl = $responseU->url;
            header('Location: ' . $goUrl);
            exit();
        }

        header('Location: /u/profile');
        exit();
    }
}

```

### 10. Single sign on

```
global $g_config, $g_uri;

if ($g_uri == '/postloginsso') {
    $ssoToken = g_param('sso_token');
    
    $client = \geetoPod_Client\Clients::instance()->getClient(null);
    $requestV = new \geetoPod_Client\ValidateSSOTokenRequest();
    $requestV->company = $g_config['company'];
    $requestV->ssoToken = $ssoToken;
    $responseV = $client->loginSSO($requestV);

    header('Location: /u/profile');
    exit();
}

if ($g_uri == '/loginsso') {
    $services = \geetoPod_Client\Services::instance();
    $requestU = new \geetoPod_Client\GetSSOTokenUrlRequest();
    $requestU->company = $g_config['company'];
    $requestU->redirectUrl = $g_config['web.url'] . "/postloginsso";
    $responseU = $services->getSSOTokenUrl($requestU);
    $goUrl = $responseU->url;
    header('Location: ' . $goUrl);
    exit();
}
```

### 11. Login with Github

```
global $g_config, $g_uri;

if ($g_uri == '/social/login/github') {
    $clients = g_clients();
    $services = g_services();

    $requestV = new \geetoPod_Client\SocialLoginUrlRequest();
    $requestV->company = $g_config['company'];
    $requestV->provider = 'github';
    $requestV->redirectUrl = $g_config['web.url'] . '/social/callback/github';
    $responseV = $services->socialLoginUrl($requestV);
    $url = $responseV->url;

    header('Location: ' . $url);
    exit();
} else if ($g_uri == '/social/callback/github') {
    $verifiedToken = g_param('verifiedToken');

    $clients = g_clients();
    $services = g_services();

    $requestV = new \geetoPod_Client\SocialLoginProcessRequest();
    $requestV->company = $g_config['company'];
    $requestV->verifiedToken = $verifiedToken;
    $requestV->hasSSO = true;
    $responseV = $clients->getClient(null)->loginSocial($requestV);

    $requestU = new \SSO_Pod_Client\PutSSOTokenUrlRequest();
    $requestU->ssoToken = $responseV->ssoToken;
    $requestU->company = $g_config['company'];
    $requestU->redirectUrl = $g_config['web.url'] . "/postlogin";
    $responseU = $services->putSSOTokenUrl($requestU);
    $goUrl = $responseU->url;

    header('Location: ' . $goUrl);
    exit();
}
```
