<?php
// Detectar IP del cliente.
// Si openNDS no manda clientip por GET/POST, usamos REMOTE_ADDR.
$clientip  = $_GET['clientip'] ?? $_POST['clientip'] ?? $_SERVER['REMOTE_ADDR'] ?? '';
$clientmac = $_GET['clientmac'] ?? $_POST['clientmac'] ?? '';

$error = '';
$output = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $usuario = trim($_POST['usuario'] ?? '');
    $clave   = $_POST['clave'] ?? '';

    // Volvemos a detectar IP durante POST
    $ip  = $_POST['clientip'] ?? $_SERVER['REMOTE_ADDR'] ?? '';
    $mac = $_POST['clientmac'] ?? '';

    // Datos de MariaDB
    $db_host = "localhost";
    $db_user = "portaluser";
    $db_pass = "Portal12345";
    $db_name = "portal_wifi";

    $db = new mysqli($db_host, $db_user, $db_pass, $db_name);

    if ($db->connect_error) {
        die("Error de base de datos: " . htmlspecialchars($db->connect_error));
    }

    // La contraseña en la base está guardada con SHA2('1234', 256)
    $hash = hash('sha256', $clave);

    $stmt = $db->prepare("SELECT id FROM usuarios WHERE usuario=? AND password=? AND activo=1 LIMIT 1");

    if (!$stmt) {
        die("Error preparando consulta: " . htmlspecialchars($db->error));
    }

    $stmt->bind_param("ss", $usuario, $hash);
    $stmt->execute();
    $stmt->store_result();

    if ($stmt->num_rows === 1) {

        if ($ip === '') {
            $error = "No se pudo detectar la IP del cliente.";
        } else {
            // Validación básica de IP para evitar comandos peligrosos
            if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                $error = "IP inválida detectada: " . htmlspecialchars($ip);
            } else {
                $safeIp = escapeshellarg($ip);

                // Autorizar cliente en openNDS
                $cmd = "sudo /usr/bin/ndsctl auth $safeIp 2>&1";
                $output = shell_exec($cmd);

                ?>
                <!doctype html>
                <html lang="es">
                <head>
                    <meta charset="utf-8">
                    <title>Autenticado</title>
                    <meta name="viewport" content="width=device-width, initial-scale=1">
                    <style>
                        body {
                            font-family: Arial, sans-serif;
                            background: #f2f2f2;
                            display: flex;
                            align-items: center;
                            justify-content: center;
                            min-height: 100vh;
                            margin: 0;
                        }
                        .box {
                            background: white;
                            width: 360px;
                            padding: 25px;
                            border-radius: 12px;
                            box-shadow: 0 4px 18px rgba(0,0,0,.15);
                            text-align: center;
                        }
                        .ok {
                            color: green;
                            font-weight: bold;
                        }
                        pre {
                            text-align: left;
                            background: #eee;
                            padding: 10px;
                            overflow: auto;
                            font-size: 12px;
                        }
                    </style>
                    <script>
                        setTimeout(function() {
                            window.location.href = "http://neverssl.com";
                        }, 3000);
                    </script>
                </head>
                <body>
                    <div class="box">
                        <h2 class="ok">Autenticado correctamente</h2>
                        <p>Ya puedes navegar por internet.</p>

                        <p><b>IP autorizada:</b> <?= htmlspecialchars($ip) ?></p>
                        <p><b>MAC:</b> <?= htmlspecialchars($mac ?: 'No recibida') ?></p>

                        <pre><?= htmlspecialchars($output ?? 'Sin salida de ndsctl') ?></pre>

                        <p>Redirigiendo...</p>
                    </div>
                </body>
                </html>
                <?php
                exit;
            }
        }

    } else {
        $error = "Usuario o contraseña incorrectos.";
    }

    $stmt->close();
    $db->close();
}
?>

<!doctype html>
<html lang="es">
<head>
    <meta charset="utf-8">
    <title>Portal WiFi</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">

    <style>
        body {
            font-family: Arial, sans-serif;
            background: #f2f2f2;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            margin: 0;
        }

        .box {
            background: white;
            width: 360px;
            padding: 25px;
            border-radius: 12px;
            box-shadow: 0 4px 18px rgba(0,0,0,.15);
        }

        h2 {
            text-align: center;
            margin-top: 0;
        }

        input, button {
            width: 100%;
            padding: 12px;
            margin-top: 10px;
            box-sizing: border-box;
            font-size: 15px;
        }

        button {
            background: #111;
            color: white;
            border: 0;
            cursor: pointer;
            border-radius: 5px;
        }

        button:hover {
            background: #333;
        }

        .error {
            color: red;
            background: #ffe6e6;
            padding: 10px;
            margin-bottom: 10px;
            border-radius: 5px;
            font-size: 14px;
        }

        .small {
            font-size: 12px;
            color: #666;
            margin-top: 15px;
            word-break: break-all;
        }
    </style>
</head>
<body>

<div class="box">
    <h2>Acceso WiFi</h2>

    <?php if ($error): ?>
        <div class="error"><?= htmlspecialchars($error) ?></div>
    <?php endif; ?>

    <form method="post">
        <input type="hidden" name="clientip" value="<?= htmlspecialchars($clientip) ?>">
        <input type="hidden" name="clientmac" value="<?= htmlspecialchars($clientmac) ?>">

        <input type="text" name="usuario" placeholder="Usuario" required>
        <input type="password" name="clave" placeholder="Contraseña" required>

        <button type="submit">Entrar</button>
    </form>

    <div class="small">
        IP detectada: <?= htmlspecialchars($clientip ?: 'No detectada') ?><br>
        MAC: <?= htmlspecialchars($clientmac ?: 'No recibida') ?>
    </div>
</div>

</body>
</html>