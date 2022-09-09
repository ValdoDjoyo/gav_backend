<?php

namespace App\Filters;

use CodeIgniter\Filters\FilterInterface;
use CodeIgniter\HTTP\RequestInterface;
use CodeIgniter\HTTP\ResponseInterface;
use Firebase\JWT\JWT;
use Config\Services;

class AuthFilter implements FilterInterface
{
    /**
     * Do whatever processing this filter needs to do.
     * By default it should not return anything during
     * normal execution. However, when an abnormal state
     * is found, it should return an instance of
     * CodeIgniter\HTTP\Response. If it does, script
     * execution will end and that Response will be
     * sent back to the client, allowing for error pages,
     * redirects, etc.
     *
     * @param RequestInterface $request
     * @param array|null       $arguments
     *
     * @return mixed
     */
    public function before(RequestInterface $request, $arguments = null)
    {
        // $key = getenv('JWT_SECRET');
        // // header("Access-Control-Allow-Origin: http://localhost:4200");
        // // header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
        // // header("Access-Control-Allow-Headers: Content-Type, Authorization");
        // $header = $request->getServer('HTTP_AUTHORIZATION');
        // $token = null;

        // // extract the token from the header
        // if (!empty($header)) {
        //     if (preg_match('/Bearer\s(\S+)/', $header, $matches)) {
        //         $token = $matches[1];
        //     }
        // }

        // // check if token is null or empty
        // if (is_null($token) || empty($token)) {
        //     $response = service('response');
        //     $response->setBody('Access denied');
        //     $response->setStatusCode(401);
        //     return $response;
        // }

        // try {
        //     // $decoded = JWT::decode($token, $key, array("HS256"));
        //     $decoded = JWT::decode($token, new Key($key, 'HS256'));
        // } catch (Exception $ex) {
        //     $response = service('response');
        //     $response->setBody('Access denied');
        //     $response->setStatusCode(401);
        //     return $response;
        // }

        $key = getenv('JWT_SECRET');
        $header = $request->getServer('HTTP_AUTHORIZATION');
        if (!$header) return Services::response()
            ->setJSON(['msg' => 'Token Required'])
            ->setStatusCode(ResponseInterface::HTTP_UNAUTHORIZED);
        $token = explode(' ', $header)[1];

        try {
            JWT::decode($token, $key, array('HS256'));
        } catch (\Throwable $th) {
            return Services::response()
                ->setJSON(['msg' => 'Invalid Token'])
                ->setStatusCode(ResponseInterface::HTTP_UNAUTHORIZED);
        }
    }

    /**
     * Allows After filters to inspect and modify the response
     * object as needed. This method does not allow any way
     * to stop execution of other af filters, short of
     * throwing an Exception or Error.
     *
     * @param RequestInterface  $request
     * @param ResponseInterface $response
     * @param array|null        $arguments
     *
     * @return mixed
     */
    public function after(RequestInterface $request, ResponseInterface $response, $arguments = null)
    {
        //
    }
}
