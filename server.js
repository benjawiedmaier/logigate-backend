const express = require('express');
const mysql = require('mysql');
const cors = require('cors');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

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

function sendPackageEmail(deptoID, descripcion) {
    const sql = "SELECT Residentes.Correo FROM Residentes INNER JOIN Depto_Casas ON Residentes.Deptos_Casas_ID = Depto_Casas.ID WHERE Depto_Casas.ID = ?";
    db.query(sql, deptoID, (err, result) => {
        if (err) {
            console.error("Error al obtener el correo electrónico del residente:", err);
            return;
        }

        const residentEmail = result[0].Correo;
        console.log(residentEmail);
        sendEmail(residentEmail, "Nuevo paquete recibido", descripcion);
    });
}

app.post('/sendPackageEmail', (req, res) => {
    const { deptoID, descripcion } = req.body;
    sendPackageEmail(deptoID, descripcion); // Llama a la función para enviar el correo electrónico al residente
    res.json({ status: "Success", message: "Correo electrónico enviado al residente" });
});

//seccion visitas
app.post('/createVisit', (req, res) => {
    const { rut, nombre, categoriaID, edificioID } = req.body;
    const ultimaVisita = new Date().toISOString().slice(0, 19).replace('T', ' ');

    const sql = `
        INSERT INTO Visitas (Rut, Nombre, Contador, Ultima_visita, Condominios_Edificios_ID, Categoria_ID)
        VALUES (?, ?, 0, ?, ?, ?)
        ON DUPLICATE KEY UPDATE Contador = Contador + 1, Ultima_visita = VALUES(Ultima_visita)`;

    const values = [rut, nombre, ultimaVisita, edificioID, categoriaID];

    db.query(sql, values, (err, result) => {
        if (err) {
            return sendResponse(res, "Error", err);
        }
        return sendResponse(res, "Success", "Visita agregada correctamente");
    });
});

app.post('/last5Visits', (req, res) => {
    const { edificioID } = req.body;

    const sql = `
        SELECT * FROM Visitas
        WHERE Condominios_Edificios_ID = ?
        ORDER BY Ultima_visita DESC
        LIMIT 5`;

    db.query(sql, [edificioID], (err, result) => {
        if (err) {
            return sendResponse(res, "Error", err);
        }
        return sendResponse(res, "Success", "Data retrieved", result);
    });
});

// Obtener el ID del edificio relacionado al acceso
app.post('/getEdificioID', (req, res) => {
    const { userId } = req.body;

    const sql = `
        SELECT inter.Condominio_Edificio_ID
        FROM inter
        INNER JOIN Acceso ON inter.Acceso_Rut = Acceso.Rut
        WHERE Acceso.Rut = ?`;

    db.query(sql, [userId], (err, result) => {
        if (err) {
            return res.status(500).json({ message: "Error retrieving building ID", error: err });
        }
        if (result.length > 0) {
            return res.status(200).json({ message: "Success", edificioID: result[0].Condominio_Edificio_ID });
        } else {
            return res.status(404).json({ message: "Building ID not found for this user" });
        }
    });
});

app.listen(8081, () => {
    console.log('Listening');
})