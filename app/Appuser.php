<?php

namespace App;

use Laravel\Passport\HasApiTokens;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Foundation\Auth\User as Authenticatable;

class Appuser extends Authenticatable
{
	use HasApiTokens;

    protected $fillable = ['name', 'email'];
}
