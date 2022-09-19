<?php

namespace App\Controllers;

use CodeIgniter\RESTful\ResourceController;
use CodeIgniter\API\ResponseTrait;
use App\Models\UserModel;
use \Firebase\JWT\JWT;

class UserController extends ResourceController
{
    use ResponseTrait;

    public function login()
    {
        $userModel = new UserModel();

        $login = $this->request->getVar('login');
        $password = $this->request->getVar('password');

        $user = $userModel->where('login', $login)->first();

        if (is_null($user)) {
            return $this->respond(['error' => 'login not found.'], 401);
        }

        $pwd_verify = password_verify($password, $user['password']);

        if ($password !== $user['password']) {
            return $this->respond(['error' => 'Invalid username or passwordd.'], 401);
        }

        $key = getenv('JWT_SECRET');
        $iat = time(); // current timestamp value
        $exp = $iat + 3600;

        $payload = array(
            "iss" => "Issuer of the JWT",
            "aud" => "Audience that the JWT",
            "sub" => "Subject of the JWT",
            "iat" => $iat, //Time the JWT issued at
            "exp" => $exp, // Expiration time of token
            "login" => $user['login'],
        );

        $token = JWT::encode($payload, $key, 'HS256');

        $response = [
            'message' => 'Login Succesful',
            'token' => $token
        ];

        return $this->respond($response, 200);
    }
    public function getUser()
    {
        $users = new UserModel;
        return $this->respond(['users' => $users->findAll()], 200);
    }
}
