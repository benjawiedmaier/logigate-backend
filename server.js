const express = require('express');
const mysql = require('mysql');
const cors = require('cors');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');


const twilio = require('twilio');
const accountSid = 'AC9b22e297f50cabf5e51fb0c06968f331'; // Tu Account SID de Twilio
const authToken = '89df02f4414facdf45087840df75deae';   // Tu Auth Token de Twilio
const client = new twilio(accountSid, authToken);

const nodemailer = require('nodemailer');
const app = express();
app.use(cors()) 
app.use(express.json());

const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: "testdb"
});

function hashPassword(password) {
    const salt = crypto.randomBytes(16).toString("hex");
    const hash = crypto.createHash('sha512').update(password).digest('hex');
    return {
        salt: salt,
        hash: hash
    };
}


app.post('/signup', (req, res) => {
    const { salt, hash } = hashPassword(req.body.password);

    // Primero, verifica si el RUT ya existe en la base de datos
    const sqlCheck = "SELECT * FROM Acceso WHERE Rut = ?";
    db.query(sqlCheck, req.body.rut, (err, result) => {
        if (err) {
            return res.json({status: "Error", message: err});
        }

        // Si el RUT ya existe, envía un mensaje de error
        if (result.length > 0) {
            return res.json({status: "Error", message: "Usuario (RUT) ya existente"});
        }

        // Si el RUT no existe, procede a insertar el nuevo usuario
        const sqlAcceso = "INSERT INTO Acceso (Rut, Correo, Rol_ID, Contraseña, Salt) VALUES (?)";
        const valuesAcceso = [
            req.body.rut,
            req.body.email,
            3, // Rol siempre es 'conserje' con ID 3
            hash,
            salt,
        ];
        db.query(sqlAcceso, [valuesAcceso], (err, result) => {
            if(err){
                return res.json({status: "Error", message: err});
            }
            const sqlInter = "INSERT INTO inter (Acceso_Rut, Condominio_Edificio_ID) VALUES (?)";
            const valuesInter = [
                req.body.rut,
                req.body.id
            ];
            db.query(sqlInter, [valuesInter], (err, result) => {
                if(err){
                    return res.json({status: "Error", message: err});
                }
                // Actualiza el inter_ID en la tabla Acceso con el ID del inter recién creado
                console.log({contraseña: req.body.password, salt: salt.toString('hex'), hash: hash});
                return res.json({status: "Success", message: "Usuario creado"});
            });
        });
    });
});

const verifyJwt = (req, res, next) => {
    const token = req.headers["access-token"];
    if (!token) {
        return res.json({status: "Error", message: "No token provided"});
    }else{
        jwt.verify(token, "SecretKey", (err, decoded) => {
            if(err){
                return res.json({status: "Error", message: "Invalid token"});
            }
            req.userRut = decoded.id;
            next();
        });
    }
}

app.get('/checkauth',verifyJwt ,(req, res) => {
    return res.json("Authenticado");
});

app.post('/grabinfopark', (req, res) => {
    const sql = `
        SELECT Estacionamientos.ID, Estacionamientos.Numero
        FROM Estacionamientos
        WHERE Estacionamientos.ID NOT IN (
            SELECT Estacionamientos_ID
            FROM Estacionamiento_Visitas
            WHERE Tiempo_de_salida IS NULL
        )
    `;

    db.query(sql, req.body.id, (err, result) => {
        if (err) {
            return res.json({ status: "Error", message: err });
        }
        return res.json(result);
    });
});


app.post('/grabinfodepto', (req, res) => {
    const sql = `
        SELECT Depto_Casas.ID, Depto_Casas.Numero
        FROM Depto_Casas
        JOIN inter ON Depto_Casas.Condominios_Edificios_ID = inter.Condominio_Edificio_ID
        JOIN Acceso ON inter.Acceso_Rut = Acceso.Rut
        WHERE Acceso.Rut = ?`;

    db.query(sql, req.body.id, (err, result) => {
        if (err) {
            return res.json({ status: "Error", message: err });
        }
        return res.json(result);
    });
});



app.post('/login', (req, res) => {
    const sql = "SELECT * FROM Acceso WHERE Correo = ?";

    db.query(sql, req.body.email, (err, result) => {
        if (err) {
            return res.json({status: "Error", message: err});
        }

        if (result.length === 0) {
            return res.json({status: "Error", message: "Usuario no encontrado"});
        }

        const user = result[0];
        const salt = user.Salt;
        
        const hash = crypto.createHash('sha512').update(req.body.password).digest('hex');
        //const hash = crypto.pbkdf2Sync((req.body.password).toString("utf8"), salt, 1000, 64, `sha512`).toString(`hex`);
        //const hash = crypto.pbkdf2Sync("req.body.password", user.Salt, 1000, 64, `sha512`).toString(`hex`);
        console.log("Hash de la contraseña ingresada:", hash);
        if (hash === user.Contraseña) {
            const id = user.Rut;
            const token = jwt.sign({id}, "SecretKey", {expiresIn: "1h"});
            return res.json({Login: true, token, user});
        } else {
            return res.json({status: "Error", message: "Contraseña incorrecta", clave: user.Contraseña, clavehash: hash, salt: salt, usersalt: user.Salt});
        }
    });
});

//Seccion estacionamiento

app.post('/addParkVisit', (req, res) => {
    const { patente, deptoID, estacionamientoID } = req.body;
    // Obtener el timestamp actual
    const tiempoDeEntrada = new Date().toISOString().slice(0, 19).replace('T', ' ');

    // Realizar la inserción en la tabla Estacionamiento_Visitas
    const sql = "INSERT INTO Estacionamiento_Visitas (Estacionamientos_ID, Deptos_Casas_ID, Patente, Tiempo_de_Entrada) VALUES (?, ?, ?, ?)";
    const values = [estacionamientoID, deptoID, patente, tiempoDeEntrada];

    db.query(sql, values, (err, result) => {
        if (err) {
            return res.json({ status: "Error", message: err });
        }
        return res.json({ status: "Success", message: "Visita agregada correctamente" });
    });
});

app.get('/occupiedParking', (req, res) => {
    const sql = `
        SELECT Estacionamientos.Numero AS 'Numero de Estacionamiento', 
               Depto_Casas.Numero AS 'Numero de Departamento', 
               Estacionamiento_Visitas.Patente, 
               Estacionamiento_Visitas.Tiempo_de_Entrada,
               Estacionamiento_Visitas.ID
        FROM Estacionamiento_Visitas
        JOIN Estacionamientos ON Estacionamientos.ID = Estacionamiento_Visitas.Estacionamientos_ID
        JOIN Depto_Casas ON Depto_Casas.ID = Estacionamiento_Visitas.Deptos_Casas_ID
        WHERE Estacionamiento_Visitas.Tiempo_de_salida IS NULL
    `;

    db.query(sql, (err, result) => {
        if (err) {
            return res.json({ status: "Error", message: err });
        }
        return res.json(result);
    });
});

app.get('/occupiedParkingid', (req, res) => {
    const userRut = req.query.userRut;
    if (!userRut) {
        return res.json({ status: "Error", message: "El campo userRut es obligatorio" });
    }

    const sql = `
        SELECT Estacionamientos.Numero AS 'Numero de Estacionamiento', 
               Depto_Casas.Numero AS 'Numero de Departamento', 
               Estacionamiento_Visitas.Patente, 
               Estacionamiento_Visitas.Tiempo_de_Entrada,
               Estacionamiento_Visitas.ID
        FROM Estacionamiento_Visitas
        JOIN Estacionamientos ON Estacionamientos.ID = Estacionamiento_Visitas.Estacionamientos_ID
        JOIN Depto_Casas ON Depto_Casas.ID = Estacionamiento_Visitas.Deptos_Casas_ID
        JOIN Condominio_Edificio ON Condominio_Edificio.ID = Estacionamientos.Condominios_Edificios_ID
        JOIN inter ON inter.Condominio_Edificio_ID = Condominio_Edificio.ID
        JOIN Acceso ON Acceso.Rut = inter.Acceso_Rut
        WHERE Estacionamiento_Visitas.Tiempo_de_salida IS NULL
          AND Acceso.Rut = ?
    `;

    db.query(sql, [userRut], (err, result) => {
        if (err) {
            return res.json({ status: "Error", message: err });
        }
        return res.json(result);
    });
});


app.put('/checkout/:visitId', (req, res) => {
    const visitId = req.params.visitId;
    const tiempoDeSalida = new Date();

    const sql = "UPDATE Estacionamiento_Visitas SET Tiempo_de_salida = ? WHERE ID = ?";
    const values = [tiempoDeSalida, visitId];

    db.query(sql, values, (err, result) => {
        if (err) {
            return res.json({ status: "Error", message: err });
        }
        return res.json({ status: "Success", message: "Hora de salida agregada correctamente" });
    });
});


app.delete('/deletevisit/:visitId', (req, res) => {
    const visitId = req.params.visitId;
    const sql = "DELETE FROM Estacionamiento_Visitas WHERE ID = ?";
    
    db.query(sql, visitId, (err, result) => {
        if (err) {
            return res.json({ status: "Error", message: err });
        }
        return res.json({ status: "Success", message: "Registro eliminado correctamente" });
    });
});
  
app.post('/maxParkingTime', (req, res) => {
    const userId = req.body.id; // ID del usuario guardado en el local storage
    const sql = `
        SELECT Tiempo_max
        FROM Condominio_Edificio
        JOIN inter ON Condominio_Edificio.ID = inter.Condominio_Edificio_ID
        JOIN Acceso ON inter.Acceso_Rut = Acceso.Rut
        WHERE Acceso.Rut = ?
    `;

    db.query(sql, userId, (err, result) => {
        if (err) {
            return res.json({ status: "Error", message: err });
        }
        if (result.length > 0) {
            const maxParkingTime = result[0].Tiempo_max;
            return res.json({ status: "Success", maxParkingTime });
        } else {
            return res.json({ status: "Error", message: "Usuario no encontrado en condominio" });
        }
    });
});

app.get('/checkOvertime', verifyJwt, (req, res) => {
    const userRut = req.userRut;
    
    const sql = `
        SELECT Estacionamientos.Numero AS 'Numero de Estacionamiento', 
               Depto_Casas.Numero AS 'Numero de Departamento', 
               Estacionamiento_Visitas.Patente, 
               Estacionamiento_Visitas.Tiempo_de_Entrada,
               Estacionamiento_Visitas.ID,
               Condominio_Edificio.Tiempo_max
        FROM Estacionamiento_Visitas
        JOIN Estacionamientos ON Estacionamientos.ID = Estacionamiento_Visitas.Estacionamientos_ID
        JOIN Depto_Casas ON Depto_Casas.ID = Estacionamiento_Visitas.Deptos_Casas_ID
        JOIN Condominio_Edificio ON Estacionamientos.Condominios_Edificios_ID = Condominio_Edificio.ID
        JOIN inter ON Estacionamientos.Condominios_Edificios_ID = inter.Condominio_Edificio_ID
        WHERE inter.Acceso_Rut = ?
    `;

    db.query(sql, userRut, (err, result) => {
        if (err) {
            return res.json({ status: "Error", message: err });
        }

        const currentTime = new Date();
        const overtimeEntries = result.filter(entry => {
            const entryTime = new Date(entry.Tiempo_de_Entrada);
            const diffMinutes = (currentTime - entryTime) / (1000 * 60);
            return diffMinutes > entry.Tiempo_max;
        });

        return res.json({ status: "Success", overtimeEntries });
    });
});

// seccion paquetes

app.post('/addPackage', (req, res) => {
    const { descripcion, deptoID } = req.body;
    const tiempoDeEntrada = new Date();
    //const tiempoDeEntrada = new Date(ahora.getTime() + (ahora.getTimezoneOffset() * 60000));
    
  
    const sql = "INSERT INTO Paquetes (Descripción, Deptos_Casas_ID, Tiempo_de_entrada) VALUES (?, ?, ?)";
    const values = [descripcion, deptoID, tiempoDeEntrada];
  
    db.query(sql, values, (err, result) => {
      if (err) {
        return res.json({ status: "Error", message: err });
      }
      return res.json({ status: "Success", message: "Paquete agregado correctamente" });
    });
});
  
app.get('/getPackages', (req, res) => {
    const sql = "SELECT P.*, DC.Numero AS NumeroDepartamento FROM Paquetes AS P INNER JOIN Depto_Casas AS DC ON P.Deptos_Casas_ID = DC.ID WHERE P.Estado = 'no entregado'";

    db.query(sql, (err, result) => {
        if (err) {
            return res.json({ status: "Error", message: err });
        }
        return res.json(result);
    });
});

app.get('/getPackagesid', (req, res) => {
    const userRut = req.query.userRut;
    const sql = `
        SELECT P.*, DC.Numero AS NumeroDepartamento 
        FROM Paquetes AS P 
        INNER JOIN Depto_Casas AS DC ON P.Deptos_Casas_ID = DC.ID 
        INNER JOIN Inter AS I ON DC.ID = I.Condominio_Edificio_ID
        WHERE P.Estado = 'no entregado' 
        AND I.Acceso_Rut = ?;
        `;

    db.query(sql, [userRut], (err, result) => {
        if (err) {
            return res.json({ status: "Error", message: err });
        }
        return res.json(result);
    });
});

  
app.delete('/deletePackage/:packageId', (req, res) => {
    const packageId = req.params.packageId;
    const sql = "DELETE FROM Paquetes WHERE ID = ?";
  
    db.query(sql, packageId, (err, result) => {
      if (err) {
        return res.json({ status: "Error", message: err });
      }
      return res.json({ status: "Success", message: "Paquete eliminado correctamente" });
    });
});

app.put('/deliverPackage/:packageId', (req, res) => {
    const packageId = req.params.packageId;
    const ahora = new Date();
    //const tiempoDeSalida = new Date(ahora.getTime() + (ahora.getTimezoneOffset() * 60000));
    const tiempoDeSalida = new Date();

    const sql = "UPDATE Paquetes SET Estado = 'entregado', Tiempo_de_salida = ? WHERE ID = ?";
    const values = [tiempoDeSalida, packageId];

    db.query(sql, values, (err, result) => {
        if (err) {
            return res.json({ status: "Error", message: err });
        }
        return res.json({ status: "Success", message: "Paquete marcado como entregado" });
    });
});

app.get('/residents/:deptoID', (req, res) => {
    const deptoID = req.params.deptoID;
    
    const sql = `
        SELECT *
        FROM Residentes
        WHERE Deptos_Casas_ID = ?
    `;
    
    db.query(sql, [deptoID], (err, result) => {
        if (err) {
            return res.json({ status: "Error", message: err });
        }
        return res.json(result);
    });
});

// Función para enviar el correo electrónico
function sendEmail(to, subject, body) {
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: 'logi.gate.alert@gmail.com',
            pass: 'fssg axkd ibzq ymyc'
        }
    });

    const mailOptions = {
        from: 'tu_correo@gmail.com',
        to: to,
        subject: subject,
        text: body
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.error("Error al enviar el correo electrónico:", error);
        } else {
            console.log("Correo electrónico enviado:", info.response);
        }
    });
}

function sendPackageEmail(deptoID, descripcion, correo_usuario) {
    const sql = "SELECT Residentes.Correo FROM Residentes INNER JOIN Depto_Casas ON Residentes.Deptos_Casas_ID = Depto_Casas.ID WHERE Depto_Casas.ID = ?";
    db.query(sql, deptoID, (err, result) => {
        if (err) {
            console.error("Error al obtener el correo electrónico del residente:", err);
            return;
        }

        const residentEmail = result[0].Correo;
        console.log(correo_usuario);
        sendEmail(correo_usuario, "Nuevo paquete recibido", descripcion);
    });
}

function sendWhatsApp(to, body) {
    client.messages.create({
        body: body,
        from: 'whatsapp:+14155238886', // El número de Twilio Sandbox para WhatsApp
        to: `whatsapp:${to}` // El número de destino debe tener el prefijo 'whatsapp:'
    })
    .then(message => console.log("Mensaje de WhatsApp enviado:", message.sid))
    .catch(error => console.error("Error al enviar el mensaje de WhatsApp:", error));
}

function sendPackageWhatsApp(deptoID, descripcion, phoneNumbers) {
    console.log(phoneNumbers);
    const messageBody = "Nuevo paquete recibido: " + descripcion;

    if (Array.isArray(phoneNumbers)) {
        phoneNumbers.forEach(phoneNumber => {
            sendWhatsApp(phoneNumber, messageBody);
        });
    } else {
        sendWhatsApp(phoneNumbers, messageBody);
    }
}


app.post('/sendPackageEmail', (req, res) => {
    const { deptoID, descripcion, correos_usuarios, telefonos_usuarios} = req.body;
    console.log(correos_usuarios)
    console.log(telefonos_usuarios)
    sendPackageEmail(deptoID, descripcion, correos_usuarios); // Llama a la función para enviar el correo electrónico al residente
    sendPackageWhatsApp(deptoID, descripcion, telefonos_usuarios);
    res.json({ status: "Success", message: "Correo electrónico enviado al residente" });
});

//seccion visitas

function addNewVisit(rut, nombre, edificioID, categoriaID, callback) {
    const sql = `
        INSERT INTO Visitas (Rut, Nombre, Contador, Ultima_visita, Condominios_Edificios_ID, Categoria_ID)
        VALUES (?, ?, 1, NOW(), ?, ?)
    `;
    const values = [rut, nombre, edificioID, categoriaID];

    db.query(sql, values, (err, result) => {
        if (err) {
            return callback(err, null);
        }
        return callback(null, result);
    });
}

// Añadimos una nueva ruta para manejar la solicitud de agregar una nueva visita
app.post('/addNewVisit', (req, res) => {
    const { rut, nombre, edificioID, categoriaID } = req.body;

    addNewVisit(rut, nombre, edificioID, categoriaID, (err, result) => {
        if (err) {
            return res.json({ status: "Error", message: err.message });
        }
        return res.json({ status: "Success", message: "Visita agregada correctamente" });
    });
});

function checkVisit(rut, edificioId, callback) {
    const sql = `
        SELECT Contador, Categoria_ID
        FROM Visitas
        WHERE Rut = ? AND Condominios_Edificios_ID = ?
    `;
    const values = [rut, edificioId];

    db.query(sql, values, (err, results) => {
        if (err) {
            return callback(err, null);
        }
        if (results.length > 0) {
            return callback(null, results[0]); // Devolvemos el primer resultado encontrado
        } else {
            return callback(null, null); // No se encontró ninguna visita
        }
    });
}

function incrementVisitCounter(rut, edificioId, callback) {
    const sql = `
        UPDATE Visitas
        SET Contador = Contador + 1, Ultima_visita = NOW()
        WHERE Rut = ? AND Condominios_Edificios_ID = ?
    `;
    const values = [rut, edificioId];

    db.query(sql, values, (err, results) => {
        if (err) {
            return callback(err, null);
        }
        if (results.affectedRows > 0) {
            return callback(null, { status: "Success", message: "Contador y última visita actualizados" });
        } else {
            return callback(null, { status: "Not Found", message: "Visita no encontrada" });
        }
    });
}


function checkAndIncrementVisitCounter(rut, edificioId, callback) {
    checkVisit(rut, edificioId, (err, visit) => {
        if (err) {
            return callback(err, null);
        }
        if (visit) {
            incrementVisitCounter(rut, edificioId, (err, result) => {
                if (err) {
                    return callback(err, null);
                }
                return callback(null, result);
            });
        } else {
            return callback(null, { status: "Not Found", message: "Visita no encontrada" });
        }
    });
}

app.post('/checkAndIncrementVisitCounter', (req, res) => {
    const { rut, edificioId } = req.body;

    checkAndIncrementVisitCounter(rut, edificioId, (err, result) => {
        if (err) {
            return res.json({ status: "Error", message: err.message });
        }
        return res.json(result);
    });
});
// Ruta para manejar la verificación de visitas
app.post('/checkVisit', (req, res) => {
    const { rut, edificioId } = req.body;

    checkVisit(rut, edificioId, (err, result) => {
        if (err) {
            return res.json({ status: "Error", message: err.message });
        }
        if (result) {
            return res.json({ status: "Success", contador: result.Contador, categoriaID: result.Categoria_ID });
        } else {
            return res.json({ status: "Not Found", message: "Visita no encontrada" });
        }
    });
});

// Obtener el ID del edificio relacionado al acceso
app.get('/getEdificioId', (req, res) => {
    const userId = req.query.userId;
    console.log(userId)
    const sql = `
        SELECT inter.Condominio_Edificio_ID
        FROM inter
        INNER JOIN Acceso ON inter.Acceso_Rut = Acceso.Rut
        WHERE Acceso.Rut = ?`;

    db.query(sql, [userId], (err, result) => {
        if (err) {
            return res.status(500).json({ message: "Error retrieving building ID", error: err });
        }
        if (result.length > 0) { // Corrección aquí
            return res.status(200).json({ message: "Success", edificioID: result[0].Condominio_Edificio_ID });
        } else {
            return res.status(405).json({ message: "Building ID not found for this user" });
        }
    });
});


app.get('/getCategorias', (req, res) => {
    const sql = "SELECT * FROM Categoria;";

    db.query(sql, (err, result) => {
        if (err) {
            return res.json({ status: "Error", message: err });
        }
        return res.json(result);
    });
});

// imagenes



app.listen(8081, () => {
    console.log('Listening');
})