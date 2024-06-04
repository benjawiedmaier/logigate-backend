const express = require('express');
const mysql = require('mysql');
const cors = require('cors');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');


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
        JOIN inter ON Estacionamientos.Condominios_Edificios_ID = inter.Condominio_Edificio_ID
        JOIN Acceso ON inter.Acceso_Rut = Acceso.Rut
        LEFT JOIN Estacionamiento_Visitas ON Estacionamientos.ID = Estacionamiento_Visitas.Estacionamientos_ID
        WHERE Acceso.Rut = ? AND Estacionamiento_Visitas.ID IS NULL
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
    `;

    db.query(sql, (err, result) => {
        if (err) {
            return res.json({ status: "Error", message: err });
        }
        return res.json(result);
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
  


app.listen(8081, () => {
    console.log('Listening');
})