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
        // $userModel = new UserModel();

        // $login = $this->request->getVar('login');
        // $password = $this->request->getVar('password');

        // $user = $userModel->where('login', $login)->first();

        // if (is_null($user)) {
        //     return $this->respond(['error' => 'Invalid username.'], 401);
        // }

        // $pwd_verify = password_verify($password, $user['password']);

        // if ($password !== $user['password']) {
        //     return $this->respond(['error' => 'Invalid  or password.','data'=>$password], 401);
        // }

        // $key = getenv('JWT_SECRET');
        $iat = time(); // current timestamp value
        $exp = $iat + 3600;

        // $payload = array(
        //     "iss" => "Issuer of the JWT",
        //     "aud" => "Audience that the JWT",
        //     "sub" => "Subject of the JWT",
        //     "iat" => $iat, //Time the JWT issued at
        //     "exp" => $exp, // Expiration time of token
        //     "login" => $user['login'],
        // );

        // $token = JWT::encode($payload, $key, 'HS256');

        // $response = [
        //     'message' => 'Login Succesful',
        //     'token' => $token
        // ];

        // return $this->respond($response, 200);
        
        helper(['form']);
        $rules = [
            'login' => 'required',
            'password' => 'required|min_length[6]'
        ];
        if (!$this->validate($rules)) return $this->fail($this->validator->getErrors());
        $model = new UserModel();
        $user = $model->where("login", $this->request->getPost('login'))->first();
        if (!$user) return $this->failNotFound('login Not Found');

        //$verify = password_verify($this->request->getVar('password'), $user['password']);
        if ($this->request->getPost('password') !== $user['password']) return $this->fail('Wrong Password');

        $key = getenv('JWT_SECRET');
        $payload = array(
            "iss" => "http://localhost:3000",
            "iat" => $iat,
            "exp" => $exp,
            "uid" => $user['id'],
            "login" => $user['login']
        );

        $token = JWT::encode($payload, $key, 'HS256');

        $response = [
            'message' => 'Login Succesful',
            'token' => $token
        ];

        return $this->respond($response, 200);
    }
    public function register()
    {
        $rules = [
            'login' => ['rules' => 'required|min_length[4]|max_length[255]|valid_login|is_unique[users.login]'],
            'password' => ['rules' => 'required|min_length[8]|max_length[255]'],
            'confirm_password'  => ['label' => 'confirm password', 'rules' => 'matches[password]']
        ];


        if ($this->validate($rules)) {
            $model = new UserModel();
            $data = [
                'login'    => $this->request->getVar('login'),
                'password' => password_hash($this->request->getVar('password'), PASSWORD_DEFAULT)
            ];
            $model->save($data);

            return $this->respond(['message' => 'Registered Successfully'], 200);
        } else {
            $response = [
                'errors' => $this->validator->getErrors(),
                'message' => 'Invalid Inputs'
            ];
            return $this->fail($response, 409);
        }
    }
    public function getUser()
    {
        $users = new UserModel;
        return $this->respond(['users' => $users->findAll()], 200);
    }
}
