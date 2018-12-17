<?php

namespace App\Http\Controllers\Api;

use Auth;
use Route;
use App\Appuser;
use App\Traits\PassportToken;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;

class LoginController extends Controller
{
	use PassportToken;

	protected $user;

	public function __construct(Appuser $appuser) {
		$this->user = $appuser;
	}


    public function login(Request $request) {

    	$this->validate($request, [
    		'name'		=> 'required|string|max:191',
    		'email'		=> 'required|string|email|unique:appusers|max:191'
    	]);

    	$new_user =  $this->user->create([
    		'name' => $request->name,
    		'email' => $request->email

    	]);

    	return $this->getBearerTokenByUser($new_user, 2, true);
    }

    public function refreshToken(Request $request) {
        $client_id = env("PASSWORD_CLIENT_ID");
        $client_secret = env("PASSWORD_CLIENT_SECRET");
       
        $refresh_token = $request->refresh_token;
        $tokenRequest = $request->create('/oauth/token', 'POST');
        $request->request->add([
            "client_id"     => $client_id,
            "client_secret" => $client_secret,
            "grant_type"    => "refresh_token",
            "refresh_token" => $refresh_token,
        ]);

        $response = Route::dispatch($tokenRequest);

        $json = (array) json_decode($response->getContent());

        return response()->json($json);
    }

    public function getUsers() {
        return Auth::user()->token();
    	return $this->user->get();
    }
}
