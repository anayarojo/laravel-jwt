# Laravel JWT
Proyecto en Laravel con autenticación JWT

### Inicio rápido

Comando para clonar proyecto:

###### HTTPS
```php
git clone https://github.com/anayarojo/laravel-jwt.git
```

###### SSH
```php
git clone git@github.com:anayarojo/laravel-jwt.git
```

Comando para ir a la carpeta del proyecto:
```php
cd laravel-jwt
```

Comando para instalar los paquetes composer:
```php
composer install
```

Comando para instalar los paquetes de node:
```php
npm install
```
### API
<details>
  <summary>Mostrar</summary><p></p>

#### Register

Method: `POST`

URL: `{{host}}/api/register`

Body:
```json
{
	"name": "{{name}}",
	"email": "{{email}}",
	"password": "{{password}}",
	"password_confirmation": "{{password}}"
}
```

Response:
```json
{
    "user": {
        "name": "Test1",
        "email": "test1@email.com",
        "updated_at": "2020-03-26 19:05:51",
        "created_at": "2020-03-26 19:05:51",
        "id": 2
    },
    "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOlwvXC9sYXJhdmVsLWp3dC5yYW5heWFyb2pvLmNvbVwvXC9hcGlcL3JlZ2lzdGVyIiwiaWF0IjoxNTg1MjQ5NTUxLCJleHAiOjE1ODUyNTMxNTEsIm5iZiI6MTU4NTI0OTU1MSwianRpIjoidHlrMlpkVXhwZTF6bDcybyIsInN1YiI6MiwicHJ2IjoiMjNiZDVjODk0OWY2MDBhZGIzOWU3MDFjNDAwODcyZGI3YTU5NzZmNyJ9.ApagcOAEUBQYL2BeEYDuiiEAK2HElOuV84mshs6ScNg"
}
```

#### Login

Method: `POST`

URL: `{{host}}/api/login`

Body:
```json
{
	"email": "{{email}}",
	"password": "{{password}}"
}
```

Response:
```json
{
    "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOlwvXC9sYXJhdmVsLWp3dC5yYW5heWFyb2pvLmNvbVwvXC9hcGlcL3JlZ2lzdGVyIiwiaWF0IjoxNTg1MjQ5NTUxLCJleHAiOjE1ODUyNTMxNTEsIm5iZiI6MTU4NTI0OTU1MSwianRpIjoidHlrMlpkVXhwZTF6bDcybyIsInN1YiI6MiwicHJ2IjoiMjNiZDVjODk0OWY2MDBhZGIzOWU3MDFjNDAwODcyZGI3YTU5NzZmNyJ9.ApagcOAEUBQYL2BeEYDuiiEAK2HElOuV84mshs6ScNg"
}
```

#### Open

Method: `GET`

URL: `{{host}}/api/open`

Response:
```json
{
    "data": "This data is open and can be accessed without the client being authenticated"
}
```

#### Closed

Method: `GET`

URL: `{{host}}/api/closed`

Headers:
```json
    "Authorization": "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOlwvXC9sYXJhdmVsLWp3dC5yYW5heWFyb2pvLmNvbVwvXC9hcGlcL2xvZ2luIiwiaWF0IjoxNTg1MTkwMDMxLCJleHAiOjE1ODUxOTM2MzEsIm5iZiI6MTU4NTE5MDAzMSwianRpIjoiS3R6bDdWckE0SXh6OE1heSIsInN1YiI6MSwicHJ2IjoiMjNiZDVjODk0OWY2MDBhZGIzOWU3MDFjNDAwODcyZGI3YTU5NzZmNyJ9.5NNXWCFh6o1d1vv-goRA8l1OhfmWFh9HHBR5fO7YRn0"
```

Response:
```json
{
    "data": "This data is open and can be accessed without the client being authenticated"
}
```

</details>

### Proceso de desarrollo

<details>
  <summary>Mostrar</summary><p></p>

Ejecutar comando para crear proyecto Laravel:
```bash
composer create-project --prefer-dist laravel/laravel laravel-jwt "5.4.*"
```

Ejecutar comando para instalar los paquetes composer:
```bash
composer install
```

Ejecutar comando para instalar los paquetes node:
```bash
npm install
```

Ejecutar comando para instalar JWT authentication:
```bash
composer require tymon/jwt-auth:dev-develop --prefer-source
```

Agregar el siguiente provider al array de providers en el archivo config/app.php:

```php
[...]
Tymon\JWTAuth\Providers\LaravelServiceProvider::class,
[...]
```

Agregar los siguientes alias al array de alias:
```bash
[...]
'JWTAuth' => Tymon\JWTAuth\Facades\JWTAuth::class, 
'JWTFactory' => Tymon\JWTAuth\Facades\JWTFactory::class,
[...]
```

Ejecutar comando para crear archivo de configuración para la autenticación JWT:
```bash
php artisan vendor:publish --provider="Tymon\JWTAuth\Providers\LaravelServiceProvider"
```

Ejecutar comando para crear llave secreta para la autenticación JWT en el archivo .env:
```bash
php artisan jwt:secret
```

Implementar JWTSubject en el modelo User de la siguiente manera:
```php
<?php

namespace App;

use Illuminate\Notifications\Notifiable;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Tymon\JWTAuth\Contracts\JWTSubject;

class User extends Authenticatable implements JWTSubject
{
    use Notifiable;

    /**
        * The attributes that are mass assignable.
        *
        * @var array
        */
    protected $fillable = [
        'name', 'email', 'password',
    ];

    /**
        * The attributes that should be hidden for arrays.
        *
        * @var array
        */
    protected $hidden = [
        'password', 'remember_token',
    ];

    public function getJWTIdentifier()
    {
        return $this->getKey();
    }
    public function getJWTCustomClaims()
    {
        return [];
    }
}
```

Configurar conexión con la base de datos en el archivo .env:
```bash
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=homestead
DB_USERNAME=homestead
DB_PASSWORD=secret
```

Ejecutar comando para crear tablas del proyecto en la base de datos:
```
php artisan migrate
```


Ejecutar comandos para crear controladores:
```bash
php artisan make:controller UserController 
php artisan make:controller DataController
```

Implementar UserController de la siguiente manera:
```php
<?php

namespace App\Http\Controllers;

use App\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;

class UserController extends Controller
{
    public function authenticate(Request $request)
    {
        $credentials = $request->only('email', 'password');

        try {
            if (! $token = JWTAuth::attempt($credentials)) {
                return response()->json(['error' => 'invalid_credentials'], 400);
            }
        } catch (JWTException $e) {
            return response()->json(['error' => 'could_not_create_token'], 500);
        }

        return response()->json(compact('token'));
    }

    public function register(Request $request)
    {
            $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:6|confirmed',
        ]);

        if($validator->fails()){
                return response()->json($validator->errors()->toJson(), 400);
        }

        $user = User::create([
            'name' => $request->get('name'),
            'email' => $request->get('email'),
            'password' => Hash::make($request->get('password')),
        ]);

        $token = JWTAuth::fromUser($user);

        return response()->json(compact('user','token'),201);
    }

    public function getAuthenticatedUser()
        {
                try {

                        if (! $user = JWTAuth::parseToken()->authenticate()) {
                                return response()->json(['user_not_found'], 404);
                        }

                } catch (Tymon\JWTAuth\Exceptions\TokenExpiredException $e) {

                        return response()->json(['token_expired'], $e->getStatusCode());

                } catch (Tymon\JWTAuth\Exceptions\TokenInvalidException $e) {

                        return response()->json(['token_invalid'], $e->getStatusCode());

                } catch (Tymon\JWTAuth\Exceptions\JWTException $e) {

                        return response()->json(['token_absent'], $e->getStatusCode());

                }

                return response()->json(compact('user'));
        }
}
```

Implementar DataController de la siguiente manera:
```php
<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class DataController extends Controller
{
        public function open() 
        {
            $data = "This data is open and can be accessed without the client being authenticated";
            return response()->json(compact('data'),200);

        }

        public function closed() 
        {
            $data = "Only authorized users can see this";
            return response()->json(compact('data'),200);
        }
}
```

Ejecutar comando para crear middleware:
```bash
php artisan make:middleware JwtMiddleware
```

Implementar JwtMiddleware de la siguiente manera:
```
<?php

namespace App\Http\Middleware;

use Closure;
use JWTAuth;
use Exception;
use Tymon\JWTAuth\Http\Middleware\BaseMiddleware;

class JwtMiddleware extends BaseMiddleware
{

    /**
        * Handle an incoming request.
        *
        * @param  \Illuminate\Http\Request  $request
        * @param  \Closure  $next
        * @return mixed
        */
    public function handle($request, Closure $next)
    {
        try {
            $user = JWTAuth::parseToken()->authenticate();
        } catch (Exception $e) {
            if ($e instanceof \Tymon\JWTAuth\Exceptions\TokenInvalidException){
                return response()->json(['status' => 'Token is Invalid']);
            }else if ($e instanceof \Tymon\JWTAuth\Exceptions\TokenExpiredException){
                return response()->json(['status' => 'Token is Expired']);
            }else{
                return response()->json(['status' => 'Authorization Token not found']);
            }
        }
        return $next($request);
    }
}
```

Agregar JwtMiddleware al array de middlewares en el archivo app/http/Kernel.php:
```php
[...]
protected $routeMiddleware = [
    [...]
    'jwt.verify' => \App\Http\Middleware\JwtMiddleware::class,
];
[...]
```

Agregar las siguientes rutas al archivo routes/api.php:
```php
[...]
Route::post('register', 'UserController@register');
Route::post('login', 'UserController@authenticate');
Route::get('open', 'DataController@open');

Route::group(['middleware' => ['jwt.verify']], function() {
    Route::get('user', 'UserController@getAuthenticatedUser');
    Route::get('closed', 'DataController@closed');
});
```

</details>
