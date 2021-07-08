//
var User = require('../models/Users');
var Session = require('../models/Sessions');
var Token = require('../models/Tokens');
var Key = require('../models/Keys');
var Confirmation = require('../models/Confirmations');
var fs = require('fs');
var axios = require('axios');
var bcrypt = require('bcrypt-nodejs');
var jwt = require('jwt-simple');
var md5 = require('md5');
var mongoosePaginate = require('mongoose-pagination');
var moment = require('moment');
//var mongoosePaginatee = require('mongoose-paginate-v2');
var service_jwt = require('../services/jwt');
var service_email = require('../services/email');
var token = require('./token');
var permit = require('./permit');
var timeout;
//--------------------------------------------New--------------------------------------------
function userCreate(req, res) {
  //console.log(JSON.stringify("REQBODYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY:"));
  //console.log(JSON.stringify(req.body.dp));
  //console.log("REQ.BODY de userCreate");
  //console.log(req.body);
  switch(req.body.typeOfUser.toLowerCase()){
    case 'root':
      setTimeout(() => {
        checkRoot(req, res);
      }, 4000);
      break;
    case 'administrator':
    case 'tuser':
    case 'merchant':
    case 'carrier':
    case 'acopio':
    case 'productor':
    case 'consumer':
      checkEmail(req, res);
      break;
    default:
      res.status(404).send({message: 'El tipo de usuario "'+typeOfUser+'" no existe'});
      break;
  }
}

function checkRoot(req, res) {
    User.findOne({ typeOfUser: 'Root' }, (err, userStored) => {
        if(err) {
            res.status(500).send({ message: 'Error en la petición' });
        }else {
            if(!userStored) {
                checkEmail(req, res);
            }else {
              count = true;
              //res.status(401).send({ message: false, A: req.body.session, token: req.body.authorization /*, message: 'Ya existe un usario Root, no puedes crear más'*/ });
              //res.status(404).send({ message: 'Ya existe un usario Root, no puedes crear más' });
              var d = new Date();
              console.log('Date: '+d+'; message: deny; A: '+req.headers.session.replace(/['"]+/g, '')+'; tokenNANB: '+req.headers.authorization.replace(/['"]+/g, '')+'');
              res.status(200).send({ message: 'deny', A: req.headers.session.replace(/['"]+/g, ''), tokenNANB: req.headers.authorization.replace(/['"]+/g, '')});
            }
        }
    });
}

function checkEmail(req, res){
  User.findOne({email: req.body.email.toLowerCase()}, (err, emailStored) => {
    if(err){
      res.status(500).send({ message: 'Error en la petición' });
    }else{
      if(!emailStored){
        switch(req.body.typeOfUser.toLowerCase()){
          case 'root':
            createRoot(req, res);
            break;
          case 'administrator':
            createAdministrator(req, res);
            break;
          case 'tuser':
          case 'merchant':
          case 'carrier':
          case 'acopio':
          case 'productor':
            createTUser(req, res);
            break;
          case 'consumer':
            createConsumer(req, res);
            break;
          default:
            res.status(404).send({ message: 'Default case (checkEmail) if exists a emergency' });
            break;
        }
      }else{
        count = true;
        //console.log("Entré aquí - "+emailStored);
        res.status(404).send({ message: 'Ya existe un usuario con el email: '+email });
      }
    }
  });
}

function createRoot(req, res){
  //console.log(req.body);
  var ip = req.header('x-forwarded-for') || req.connection.remoteAddress;
  var query = { sessionID: req.headers.session.replace(/['"]+/g, ''), token: req.headers.authorization.replace(/['"]+/g, '') };
	Session.findOne(query, (err, sessionStored) => {
		if(err){
			res.status(500).send({message: 'Error en la petición'});
		}else{
			if(!sessionStored){
        //res.status(200).send({message: 'No se encontró el dato en nuestros registros', sessionID: req.headers.session.replace(/['"]+/g, ''), token: req.headers.authorization.replace(/['"]+/g, '')});
        res.status(200).send({message: 'deny', A: req.headers.session.replace(/['"]+/g, ''), tokenNANB: req.headers.authorization.replace(/['"]+/g, '')});
			}else{
        //Count is a global var
        if (count == false) {
          count = true;
          serviceInit(req, req.headers.authorization, function(data, err) {
            if (err) {
              console.log(err);
              res.status(500).send({ message: 'Error en la petición' });
            }else {
              var user = new User();
              var rootKey = new Key();
              var auditData = data;

              user.email = req.body.email.toLowerCase();
              user.surnameA = req.body.surnameA;
              user.surnameB = req.body.surnameB;
              user.nameOfUser = req.body.nameOfUser;
              user.typeOfUser = req.body.typeOfUser;
              user.ip = ip;
              user.status = req.body.status;
              user.creationDate = req.body.creationDate;
              user.initialToken = req.headers.authorization;
              user.dp = req.body.dp; //DP ahora es un dato estático, pero debería cambiarse cuando esté lista la vista
              user.addressU = req.body.addressU;
              user.addressContract =  auditData.addCont;
              user.addressTransaction = auditData.addTran;
              rootKey.key = service_jwt.keyToken("secret");

              //Pruebas con MD5
              var jsonData = {
                email: req.body.email.toLowerCase(),
                password: req.body.password,
                surnameA: req.body.surnameA,
                surnameB: req.body.surnameB,
                nameOfUser: req.body.nameOfUser,
                typeOfUser: req.body.typeOfUser,
                status: req.body.status,
                creationDate: req.body.creationDate,
                //initialToken: req.body.initialToken,
                addressU: req.body.addressU,
                typeOfOperation: req.body.typeOfOperation,
                nameOfOperation: req.body.nameOfOperation,
                dp: req.body.dp
              };
              //console.log(JSON.stringify(jsonData));
              var hashX = md5(JSON.stringify(jsonData));

              if(user.initialToken == auditData.Token && req.body.hashX == hashX && countTwo == false){
                countTwo = true;
                //REVISAR SI EXISTE EL TIPO DE OPERACIÓN QUE SE ESTÁ EJECUTANDO
                if(req.body.password){
                  //Encriptar contraseñas
                  bcrypt.hash(req.body.password, null, null, function(err, hash){
                    user.password = hash;
                    if(user.email != null && user.password != null && user.addressContract != null && user.addressTransaction != null && user.typeOfUser != null && user.initialToken != null){
                      //Guardar usuario
                      rootKey.save((err, keyStored) => {
                        if(err) {
                          res.status(500).send({ message: 'Error al guardar los datos' });
                        }else{
                          if(!keyStored) {
                            res.status(404).send({ message: 'El dato no ha sido guardado' });
                          }else{
                            user.save((err, userStored) => {
                              if(err) {
                                res.status(500).send({ message: 'Error al guardar los datos' });
                              }else{
                                if(!userStored) {
                                  res.status(404).send({ message: 'El dato no ha sido guardado' });
                                }else{
                                    Session.deleteMany({})
                                    .then(function(){
                                      //console.log('Data deleted'); // Success
                                    })
                                    .catch(function(error){
                                      //console.log(error); // Failure
                                    });
                                    //var generatedToken = service_jwt.createToken(user); //Guardar token en la base de datos
                                    token.tokenCreation(user.initialToken, user.email); //Guarda token en la base de datos
                                    req.body.typeOfOperation = 'authentication';
                                    req.body.nameOfOperation = 'loginUser';
                                    token.authenticate(req, res);
                                }
                              }
                            });
                          }
                        }
                      });
                    }else {
                      res.status(200).send({ message: 'Rellena todos los campos' });
                    }
                  });
                }else {
                  res.status(200).send({ message: 'Introduce la contraseña' });
                }
              }else if(user.initialToken != auditData.Token){
                res.status(401).send({ message: 'Errores en los datos initialToken (users): '+user.initialToken+' - Token (audit): '+auditData.Token });
              }else if(req.body.hashX != hashX){
                res.status(401).json({ message: 'Errores en los datos hashX (client): '+req.body.hashX+' - hashX(api): '+hashX });
              }else if (countTwo == true) {
                res.status(401).json({ message: 'Ha sucedido algo inesperado, intenta nuevamente pero hice la petición a audit' });
              }
            }
          });
        }else if (count == true) {
          var d = new Date();
          console.log('Date: '+d+'');
          res.status(200).send({message: 'deny', A: req.headers.session.replace(/['"]+/g, ''), tokenNANB: req.headers.authorization.replace(/['"]+/g, '')});
          //res.status(401).json({ message: 'Ha sucedido algo inesperado, intenta nuevamente' });
        }
			}
		}
	});
}

function createAdministrator(req, res){
  var ip = req.header('x-forwarded-for') || req.connection.remoteAddress;
    serviceInit(req, req.headers.authorization, function(data, err) {
        if (err) {
            res.status(500).send({ message: 'Error en la petición' });
        }else {
            var user = new User();
            var auditData = data;

            user.email = req.body.email.toLowerCase();
            user.surnameA = req.body.surnameA;
            user.surnameB = req.body.surnameB;
            user.nameOfUser = req.body.nameOfUser;
            user.typeOfUser = req.body.typeOfUser;
            user.ip = ip;
            user.status = req.body.status;
            user.creationDate = req.body.creationDate;
            user.initialToken = req.headers.authorization;
            user.dp = req.body.dp; //DP ahora es un dato estático, pero debería cambiarse cuando esté lista la vista
            user.addressU = req.body.addressU;
            user.addressContract =  auditData.y.addCont;
            user.addressTransaction = auditData.y.addTran;
            //var key = req.body.key; //REVISAR
            //var hashX = req.body.hashX; //REVISAR

            var tokeninitial = req.headers.authorization;
            var typeOfOperation = req.body.typeOfOperation;
            var nameOfOperation = req.body.nameOfOperation;
            permit.hasAccess(tokeninitial, typeOfOperation, nameOfOperation)
                .then(typeOfOperationOK => {
                    //Pruebas con MD5
                    var jsonData = {
                        email: req.body.email.toLowerCase(),
                        password: req.body.password,
                        surnameA: req.body.surnameA,
                        surnameB: req.body.surnameB,
                        nameOfUser: req.body.nameOfUser,
                        typeOfUser: req.body.typeOfUser,
                        status: req.body.status,
                        creationDate: req.body.creationDate,
                        initialToken: req.body.initialToken,
                        dp: req.body.dp,
                        addressU: req.body.addressU,
                        typeOfOperation: req.body.typeOfOperation,
                        nameOfOperation: req.body.nameOfOperation
                    };
                    var hashX = md5(JSON.stringify(jsonData));
                    /*
                    if(req.body.hashX == hashX){
                        console.log("MD5 correcto');
                    }else{
                        console.log('MD5 incorrecto');
                    }*/
                    if(typeOfOperationOK == true && user.initialToken == auditData.Token && req.body.hashX == hashX){
                        if(req.body.password){
                            //Encriptar contraseñas
                            bcrypt.hash(req.body.password, null, null, function(err, hash){
                                user.password = hash;
                                if(user.email != null && user.password != null && user.addressContract != null && user.addressTransaction != null && user.typeOfUser != null && user.initialToken != null){
                                    //Guardar usuario
                                    user.save((err, userStored) => {
                                        if(err) {
                                            return res.status(500).json({ message: 'Error al guardar los datos' });
                                        }else {
                                            if(!userStored) {
                                                return res.status(404).json({ message: 'El dato no ha sido guardado' });
                                            }else {
                                              var generatedToken = service_jwt.createToken(user); //Guardar token en la base de datos
                                                token.tokenCreation(generatedToken, user.email);
                                                return res.status(200).json({
                                                    message: generatedToken //Guardar el token
                                                });
                                            }
                                        }
                                    });
                                }else {
                                    return res.status(200).json({ message: 'Rellena todos los campos' });
                                }
                            });
                        }else {
                            return res.status(200).json({ message: 'Introduce la contraseña' });
                        }
                    }else if(user.initialToken != auditData.Token){
                        return res.status(404).json({ message: 'Errores en los datos initialToken (users) : '+user.initialToken+' - Token (audit): '+auditData.Token });
                    }else if(typeOfOperationOK != true){
                        return res.status(404).json({ message: 'No tienes permisos para crear administradores' });
                    }else if(req.body.hashX != hashX){
                        return res.status(404).json({ message: 'HashX no coincide: '+hashX });
                    }else{
                        return res.status(404).json({ message: 'Errores en los datos typeOfOperationOK: '+typeOfOperationOK+' - initialToken (users): '+user.initialToken+' - Token (audit): '+auditData.Token+' - hashX (client): '+req.body.hashX+' - hashX(api): '+hashX });
                    }
                })
                .catch(err => {
                     // never goes here
                     //console.log(err);
                     return res.status(550).json(err);
                 });
        }
    });
}

function createTUser(req, res){
  var ip = req.header('x-forwarded-for') || req.connection.remoteAddress;
    serviceInit(req, req.headers.authorization, function(data, err) {
        if (err) {
            res.status(500).send({ message: 'Error en la petición' });
        }else {
            var user = new User();
            var auditData = data;

            user.email = req.body.email.toLowerCase();
            user.surnameA = req.body.surnameA;
            user.surnameB = req.body.surnameB;
            user.nameOfUser = req.body.nameOfUser;
            user.typeOfUser = req.body.typeOfUser;
            user.ip = ip;
            user.status = req.body.status;
            user.creationDate = req.body.creationDate;
            user.initialToken = req.headers.authorization;
            user.dp = req.body.dp; //DP ahora es un dato estático, pero debería cambiarse cuando esté lista la vista
            user.addressU = req.body.addressU;
            user.addressContract =  auditData.y.addCont;
            user.addressTransaction = auditData.y.addTran;
            //var key = req.body.key; //REVISAR
            //var hashX = req.body.hashX; //REVISAR

            var tokeninitial = req.headers.authorization;
            var typeOfOperation = req.body.typeOfOperation;
            var nameOfOperation = req.body.nameOfOperation;
            permit.hasAccess(tokeninitial, typeOfOperation, nameOfOperation)
                .then(typeOfOperationOK => {
                    //Pruebas con MD5
                    var jsonData = {
                        email: req.body.email.toLowerCase(),
                        password: req.body.password,
                        surnameA: req.body.surnameA,
                        surnameB: req.body.surnameB,
                        nameOfUser: req.body.nameOfUser,
                        typeOfUser: req.body.typeOfUser,
                        status: req.body.status,
                        creationDate: req.body.creationDate,
                        initialToken: req.body.initialToken,
                        dp: req.body.dp,
                        addressU: req.body.addressU,
                        typeOfOperation: req.body.typeOfOperation,
                        nameOfOperation: req.body.nameOfOperation
                    };
                    var hashX = md5(JSON.stringify(jsonData));
                    /*
                    if(req.body.hashX == hashX){
                        console.log('MD5 correcto');
                    }else{
                        console.log('MD5 incorrecto');
                    }¨*/
                    //console.log(req.body);
                    if(typeOfOperationOK == true && user.initialToken == auditData.Token && req.body.hashX == hashX){
                        if(req.body.password){
                            //Encriptar contraseñas
                            bcrypt.hash(req.body.password, null, null, function(err, hash){
                                user.password = hash;
                                if(user.email != null && user.password != null && user.addressContract != null && user.addressTransaction != null && user.typeOfUser != null && user.initialToken != null){
                                    //Guardar usuario
                                    user.save((err, userStored) => {
                                        if(err) {
                                            return res.status(500).json({ message: 'Error al guardar los datos'+err });
                                        }else {
                                            if(!userStored) {
                                                return res.status(404).json({ message: 'El dato no ha sido guardado' });
                                            }else {
                                                var generatedToken = service_jwt.createToken(user); //Guardar token en la base de datos
                                                token.tokenCreation(generatedToken, user.email);
                                                return res.status(200).json({
                                                    message: generatedToken //Guardar el token
                                                });
                                            }
                                        }
                                    });
                                }else {
                                    return res.status(200).json({ message: 'Rellena todos los campos' });
                                }
                            });
                        }else {
                            return res.status(200).json({ message: 'Introduce la contraseña' });
                        }
                    }else if(user.initialToken != auditData.Token){
                        return res.status(404).json({ message: 'Errores en los datos initialToken (users): '+user.initialToken+' - Token (audit): '+auditData.Token });
                    }else if(typeOfOperationOK != true){
                        return res.status(404).json({ message: 'No tienes permisos para crear usuarios normales' });
                    }else if(req.body.hashX != hashX){
                        return res.status(404).json({ message: 'HashX no coincide: '+hashX });
                    }else{
                        return res.status(404).json({ message: 'Errores en los datos typeOfOperationOK: '+typeOfOperationOK+' - initialToken (users): '+user.initialToken+' - Token (audit): '+auditData.Token+' - hashX (client): '+req.body.hashX+' - hashX(api): '+hashX });
                    }
                })
                .catch(err => {
                    // never goes here
                    //console.log(err);
                    return res.status(550).json(err);
                });
        }
    });
}

function createConsumer(req, res){
    var ip = req.header('x-forwarded-for') || req.connection.remoteAddress;
    var initialToken = service_jwt.initialToken(10);
    serviceInit(req, initialToken, function(data, err) {
        if (err) {
            res.status(500).send({ message: 'Error en la petición' });
        }else {
            var user = new User();
            var auditData = data;
            let archive = fs.readFileSync('/avocado/users/public/archive/dp.txt', 'utf-8');
            //console.log(archive);
            user.email = req.body.email.toLowerCase();
            user.surnameA = req.body.surnameA;
            user.surnameB = req.body.surnameB;
            user.nameOfUser = req.body.nameOfUser;
            user.typeOfUser = req.body.typeOfUser;
            user.ip = ip;
            user.status = false; //El cliente por defecto debería asignar este valor a falso y verdaero para los demás
            user.creationDate = req.body.creationDate;
            user.initialToken = initialToken;
            user.dp = archive; //DP ahora es un dato estático, pero debería cambiarse cuando esté lista la vista
            user.addressU = req.body.addressU;
            user.addressContract =  auditData.y.addCont;
            user.addressTransaction = auditData.y.addTran;

            //Pruebas con MD5
            var jsonData = {
                email: req.body.email.toLowerCase(),
                password: req.body.password,
                surnameA: req.body.surnameA,
                surnameB: req.body.surnameB,
                nameOfUser: req.body.nameOfUser,
                typeOfUser: req.body.typeOfUser,
                status: req.body.status,
                creationDate: req.body.creationDate,
                //initialToken: initialToken,
                dp: JSON.parse(archive),
                addressU: req.body.addressU,
                typeOfOperation: req.body.typeOfOperation,
                nameOfOperation: req.body.nameOfOperation
            };
            //console.log(JSON.stringify(jsonData));
            var hashX = md5(JSON.stringify(jsonData));

            if(user.initialToken == auditData.Token && req.body.hashX == hashX /*&& archive == req.body.dp*/){
            //REVISAR SI EXISTE EL TIPO DE OPERACIÓN QUE SE ESTÁ EJECUTANDO
                if(req.body.password){
                    //Encriptar contraseñas
                    bcrypt.hash(req.body.password, null, null, function(err, hash){
                        user.password = hash;
                        if(user.email != null && user.password != null && user.addressContract != null && user.addressTransaction != null && user.typeOfUser != null && user.initialToken != null){
                            //Guardar usuario
                            user.save((err, userStored) => {
                                if(err) {
                                  //console.log(err);
                                    res.status(500).send({ message: 'Error al guardar los datos' });
                                }else{
                                    if(!userStored) {
                                        res.status(404).send({ message: 'El dato no ha sido guardado' });
                                    }else{
                                        token.tokenCreation(user.initialToken, user.email); //Guarda token en la base de datos
                                        /*res.status(200).send({
                                            message: userStored
                                        });*/
                                        //req.body.typeOfOperation = 'authentication';
                                        //req.body.nameOfOperation = 'loginUser';
                                        service_email.sendEmail(user.email);
                                        res.status(200).send({ message: true });
                                        //token.authenticate(req, res);
                                    }
                                }
                            });
                        }else {
                            res.status(200).send({ message: 'Rellena todos los campos' });
                        }
                    });
                }else {
                    res.status(200).send({ message: 'Introduce la contraseña' });
                }
            }else if(user.initialToken != auditData.Token){
                res.status(404).send({ message: 'Errores en los datos initialToken (users): '+user.initialToken+' - Token (audit): '+auditData.Token });
                //res.status(404).send({ message: 'No tienes permisos para crear usuarios de tipo administrador' });
            }else if(req.body.hashX != hashX){
                res.status(404).json({ message: 'Errores en los datos hashX (client): '+req.body.hashX+' - hashX(api): '+hashX });
            }
        }
    });
}

/*
Funciones encargada de invocar los servicios RESTful y devolver el objeto JSON correspondiente.
*/
function serviceInit(req, initialToken, next) {
    //console.log('serviceInit');
    var key = req.body.addressU;
    var hashX = req.body.hashX;
    var typeOfUser = req.body.typeOfUser;
    var initialToken = initialToken;
    var typeOfOperation = req.body.typeOfOperation;
    var data;
    var url = 'http://'+host+':'+port.audit+''+path.audit+'';
    axios.post(url, {
        key: key,
        hashX: hashX,
        typeOfUser: typeOfUser,
        Token: initialToken,
        typeOfOperation: typeOfOperation
    })
    .then(response => {
        //console.log(response.data);
        data = response.data;
        next(data, null);
    })
    .catch(error => {
        //console.log(error);
        next(null, error);
    });
}

function checkEmailtoUpdate(email) {
  return new Promise(function(resolve, reject) {
    User.findOne({ email: email.toLowerCase() })
    .then(userStored => {
      if(!userStored){
        resolve(true);
      }else{
        resolve(true);
        //resolve(userStored);
      }
    })
    .then(undefined, function(err){
			reject(err);
		});
  });
}


function userUpdate(req, res) {
  var typeOfOperation = req.body.typeOfOperation;
  var nameOfOperation = req.body.nameOfOperation;
  var email = req.params.id.toLowerCase();
  User.findOne({email: email}, (err, emailStored) => {
    if(err){
      res.status(500).send({ message: 'Error en la petición' });
    }else{
      if(!emailStored){
        res.status(200).send({ message: 'No existe este email: '+email });
      }else{
        var payload = service_jwt.decodeToken(req.headers.authorization);
        //console.log(payload);
        if(payload.life <= moment().unix()){
    			return res.status(200).json({message: 'El token ha expirado: '+payload.life});
    		}
        switch(typeOfOperation) {
          case 'update':
            if(nameOfOperation == 'updateMe') {
              //console.log(payload.typeOfUser);
              if(payload.typeOfUser == 'Consumer'){
                updateConsumer(req, res);
              }else{
                updateMe(req, res);
              }
            }else if(nameOfOperation == 'updateAdministrator') {
              updateAdministrator(req, res);
            }else if(nameOfOperation == 'updateTUser'){
              updateTUser(req, res);
            }
            break;
          default:
            return res.status(404).send({ message: 'Default case (userUpdate) if exists a emergency' });
            break;
        }
      }
    }
  });
}

function updateMe(req, res){
  var tokeninitial = req.headers.authorization;
    var typeOfOperation = req.body.typeOfOperation;
    var nameOfOperation = req.body.nameOfOperation;
    permit.hasAccess(tokeninitial, typeOfOperation, nameOfOperation)
    .then(typeOfOperationOK => {
        tokeninitial.replace(/['"]+/g, '');
        //var payload = decodeToken(tokeninitial);
        var payload = service_jwt.decodeToken(tokeninitial);
        var id = req.params.id.toLowerCase(); //CAMBIAR ESTE DATO POR LA VARIABLE QUE CONTENDRÁ LOS ID's DE LOS USUARIOS REGISTRADOS
        var jsonData = {
            email: req.body.email.toLowerCase(),
            password: req.body.password,
            surnameA: req.body.surnameA,
            surnameB: req.body.surnameB,
            nameOfUser: req.body.nameOfUser,
            typeOfUser: req.body.typeOfUser,
            status: req.body.status,
            creationDate: req.body.creationDate,
            initialToken: req.body.initialToken,
            dp: req.body.dp,
            addressU: req.body.addressU,
            typeOfOperation: req.body.typeOfOperation,
            nameOfOperation: req.body.nameOfOperation
        };
        //console.log(jsonData);
        var hashX = md5(JSON.stringify(jsonData));
        //console.log(hashX);
        /*if(req.body.hashX == hashX){
            console.log('MD5 correcto');
        }else{
            console.log('MD5 incorrecto');
        }*/
        if(typeOfOperationOK == true && id == payload._id && !req.body.email && !req.body.dp && req.body.hashX == hashX){
            //Pedir contraseña para confimar cambio
            if(req.body.password){
                bcrypt.hash(req.body.password, null, null, function(err, hash){
                    req.body.password = hash;
                    User.findOneAndUpdate({ email: id }, {password: req.body.password, surnameA: req.body.surnameA, surnameB: req.body.surnameB, nameOfUser: req.body.nameOfUser, status: req.body.status}, (err, userUpdate) => {
                        if(err){
                            res.status(500).send({message: 'Error al actualizar los datos'});
                        }else{
                            if(!userUpdate){
                                res.status(404).send({message: 'El dato no existe y no ha sido actualizado'});
                            }else{
                              token.tokenRenovation(id, userUpdate, nameOfOperation, res); //Guardar token en la base de datos
                            }
                        }
                    });
                });
            }else{
                User.findOneAndUpdate({ email: id }, {surnameA: req.body.surnameA, surnameB: req.body.surnameB, nameOfUser: req.body.nameOfUser, status: req.body.status}, (err, userUpdate) => {
                    if(err){
                        res.status(500).send({message: 'Error al actualizar los datos'});
                    }else{
                        if(!userUpdate){
                            res.status(404).send({message: 'El dato no existe y no ha sido actualizado'});
                        }else{
                          token.tokenRenovation(id, userUpdate, nameOfOperation, res); //Guardar token en la base de datos
                        }
                    }
                });
            }
        }else if(typeOfOperationOK == false){
            res.status(404).send({message: 'No tienes permisos para actualizar tus datos'});
        }else if(id != payload._id) {
            res.status(404).send({message: 'Los ID´s no coinciden'});
        }else if(req.body.email){
            res.status(404).send({message: 'No puedes actualizar tu email - contacta con el desarrollador'});
        }else if(req.body.dp){
            res.status(404).send({message: 'No puedes actualizar tus permisos'});
        }else if(req.body.hashX != hashX){
            return res.status(404).json({ message: 'HashX no coincide: '+hashX });
        }else{
            return res.status(404).json({ message: 'Errores en los datos typeOfOperationOK: '+typeOfOperationOK+' - initialToken (users): '+user.initialToken+' - Token (audit): '+auditData.Token+' - hashX (client): '+req.body.hashX+' - hashX(api): '+hashX });
        }
    })
    .catch(err => {
        // never goes here
        //console.log(err);
        return res.status(550).json(err);
    });
}

//Cambiar nombre de tokeninitial a token
function updateAdministrator(req, res){
  var tokeninitial = req.headers.authorization;
    var typeOfOperation = req.body.typeOfOperation;
    var nameOfOperation = req.body.nameOfOperation;
    permit.hasAccess(tokeninitial, typeOfOperation, nameOfOperation)
    .then(typeOfOperationOK => {
        var id = req.params.id.toLowerCase(); //CAMBIAR ESTE DATO POR LA VARIABLE QUE CONTENDRÁ LOS ID's DE LOS USUARIOS REGISTRADOS
        var bool = false;
        var query = { email: id, typeOfUser: 'Administrator' };
        User.findOne(query, (err, usersStored) => {
            if(err) {
                res.status(500).send({message: 'Error en la petición'});
            }else {
                if(!usersStored) {
                    res.status(404).send({message: 'No se ha encontrado el dato'});
                }else {
                    var jsonData = {
                        email: req.body.email.toLowerCase(),
                        password: req.body.password,
                        surnameA: req.body.surnameA,
                        surnameB: req.body.surnameB,
                        nameOfUser: req.body.nameOfUser,
                        typeOfUser: req.body.typeOfUser,
                        status: req.body.status,
                        creationDate: req.body.creationDate,
                        initialToken: req.body.initialToken,
                        dp: req.body.dp,
                        addressU: req.body.addressU,
                        typeOfOperation: req.body.typeOfOperation,
                        nameOfOperation: req.body.nameOfOperation
                    };
                    var hashX = md5(JSON.stringify(jsonData));
                    /*console.log(hashX);
                    if(req.body.hashX == hashX){
                        console.log('MD5 correcto');
                    }else{
                        console.log('MD5 incorrecto');
                    }*/
                    if(typeOfOperationOK == true && !req.body.email && req.body.hashX == hashX){
                        //Pedir contraseña para confimar cambio
                        if(req.body.password){
                            bcrypt.hash(req.body.password, null, null, function(err, hash){
                                req.body.password = hash;
                                User.findOneAndUpdate({ email: id }, {password: req.body.password, surnameA: req.body.surnameA, surnameB: req.body.surnameB, nameOfUser: req.body.nameOfUser, status: req.body.status, dp: req.body.dp}, (err, userUpdate) => {
                                    if(err){
                                        res.status(500).send({message: 'Error al actualizar los datos'});
                                    }else{
                                        if(!userUpdate){
                                            res.status(404).send({message: 'El dato no existe y no ha sido actualizado'});
                                        }else{
                                            //bool = true;
                                            //res.status(200).send({message: bool});
                                            token.tokenRenovation(id, userUpdate, nameOfOperation, res); //Guardar token en la base de datos
                                        }
                                    }
                                });
                            });
                        }else if(!req.body.password){
                            User.findOneAndUpdate({ email: id }, {surnameA: req.body.surnameA, surnameB: req.body.surnameB, nameOfUser: req.body.nameOfUser, status: req.body.status, dp: req.body.dp}, (err, userUpdate) => {
                                if(err){
                                    res.status(500).send({message: 'Error al actualizar los datos'});
                                }else{
                                    if(!userUpdate){
                                        res.status(404).send({message: 'El dato no existe y no ha sido actualizado'});
                                    }else{
                                        //bool = true;
                                        //res.status(200).send({message: bool});
                                        token.tokenRenovation(id, userUpdate, nameOfOperation, res); //Guardar token en la base de datos
                                    }
                                }
                            });
                        }
                    }else if(typeOfOperationOK == false){
                        res.status(404).send({message: 'No tienes permisos para actualizar los datos de administradores'});
                    }else if(req.body.email){
                        res.status(404).send({message: 'No puedes actualizar el email - contacta con el desarrollador'});
                    }else if(req.body.hashX != hashX){
                        return res.status(404).json({ message: 'HashX no coincide: '+hashX });
                    }else{
                        return res.status(404).json({ message: 'Errores en los datos typeOfOperationOK: '+typeOfOperationOK+' - initialToken (users): '+user.initialToken+' - Token (audit): '+auditData.Token+' - hashX (client): '+req.body.hashX+' - hashX(api): '+hashX });
                    }
                }
            }
        });
    });
}

function updateTUser(req, res){
  //console.log(req.body);
  var tokeninitial = req.headers.authorization;
    var typeOfOperation = req.body.typeOfOperation;
    var nameOfOperation = req.body.nameOfOperation;
    permit.hasAccess(tokeninitial, typeOfOperation, nameOfOperation)
    .then(typeOfOperationOK => {
        var id = req.params.id.toLowerCase(); //CAMBIAR ESTE DATO POR LA VARIABLE QUE CONTENDRÁ LOS ID's DE LOS USUARIOS REGISTRADOS
        var bool = false;
        //var query = { email: id, typeOfUser: 'TUser' };
        //var query = { email: id };

        var jsonData = {
            email: req.body.email.toLowerCase(),
            password: req.body.password,
            surnameA: req.body.surnameA,
            surnameB: req.body.surnameB,
            nameOfUser: req.body.nameOfUser,
            typeOfUser: req.body.typeOfUser,
            status: req.body.status,
            creationDate: req.body.creationDate,
            initialToken: req.body.initialToken,
            dp: req.body.dp,
            addressU: req.body.addressU,
            typeOfOperation: req.body.typeOfOperation,
            nameOfOperation: req.body.nameOfOperation
        };
        var hashX = md5(JSON.stringify(jsonData));
        /*
        console.log(hashX);
        if(req.body.hashX == hashX){
            console.log('MD5 correcto');
        }else{
            console.log('MD5 incorrecto');
        }*/
        if(typeOfOperationOK == true && !req.body.email && req.body.hashX == hashX){
            //Pedir contraseña para confimar cambio
            if(req.body.password){
                bcrypt.hash(req.body.password, null, null, function(err, hash){
                    req.body.password = hash;
                    User.findOneAndUpdate({ email: id }, {password: req.body.password, surnameA: req.body.surnameA, surnameB: req.body.surnameB, nameOfUser: req.body.nameOfUser, status: req.body.status, dp: req.body.dp}, (err, userUpdate) => {
                        if(err){
                            res.status(500).send({message: 'Error al actualizar los datos'});
                        }else{
                            if(!userUpdate){
                                res.status(404).send({message: 'El dato no existe y no ha sido actualizado'});
                            }else{
                                //bool = true;
                                //res.status(200).send({message: bool});
                                token.tokenRenovation(id, userUpdate, nameOfOperation, res); //Guardar token en la base de datos
                            }
                        }
                    });
                });
            } else if(!req.body.password){
                User.findOneAndUpdate({ email: id }, {surnameA: req.body.surnameA, surnameB: req.body.surnameB, nameOfUser: req.body.nameOfUser, status: req.body.status, dp: req.body.dp}, (err, userUpdate) => {
                    if(err){
                        res.status(500).send({message: 'Error al actualizar los datos'});
                    }else{
                        if(!userUpdate){
                            res.status(404).send({message: 'El dato no existe y no ha sido actualizado'});
                        }else{
                            //bool = true;
                            //res.status(200).send({message: bool});
                            token.tokenRenovation(id, userUpdate, nameOfOperation, res); //Guardar token en la base de datos
                        }
                    }
                });
            }
        }else if(typeOfOperationOK == false){
            res.status(404).send({message: 'No tienes permisos para actualizar los datos de usuarios normales'});
        }else if(req.body.email){
            res.status(404).send({message: 'No puedes actualizar el email - contacta con el desarrollador'});
        }else if(req.body.hashX != hashX){
            return res.status(404).json({ message: 'HashX no coincide: '+hashX });
        }else{
            return res.status(404).json({ message: 'Errores en los datos typeOfOperationOK: '+typeOfOperationOK+' - initialToken (users): '+user.initialToken+' - Token (audit): '+auditData.Token+' - hashX (client): '+req.body.hashX+' - hashX(api): '+hashX });
        }
    });
}

function updateConsumer(req, res){
  //console.log(req.body);
  checkEmailtoUpdate(req.body.email)
  .then(data => {
    if (data == true) {
      var tokeninitial = req.headers.authorization;
      var typeOfOperation = req.body.typeOfOperation;
      var nameOfOperation = req.body.nameOfOperation;
      var jsonData = {
          email: null,
          password: req.body.password,
          surnameA: req.body.surnameA,
          surnameB: req.body.surnameB,
          nameOfUser: req.body.nameOfUser,
          //addressU: req.body.addressU,
          typeOfOperation: req.body.typeOfOperation,
          nameOfOperation: req.body.nameOfOperation
      };
      if(!req.body.email){
        return res.status(200).send({message: 'El campo email no puede estar vacío'});
      }else {
        jsonData.email = req.body.email.toLowerCase();
      }
      var hashX = md5(JSON.stringify(jsonData));
      permit.hasAccess(tokeninitial, typeOfOperation, nameOfOperation)
      .then(typeOfOperationOK => {
          tokeninitial.replace(/['"]+/g, '');
          //var payload = decodeToken(tokeninitial);
          var payload = service_jwt.decodeToken(tokeninitial);
          var id = req.params.id.toLowerCase(); //CAMBIAR ESTE DATO POR LA VARIABLE QUE CONTENDRÁ LOS ID's DE LOS USUARIOS REGISTRADOS
          if(typeOfOperationOK == true && id == payload._id && !req.body.dp /*&& req.body.hashX == hashX*/){
              //Pedir contraseña para confimar cambio
              if(req.body.password){
                bcrypt.hash(req.body.password, null, null, function(err, hash){
                  req.body.password = hash;
                  User.findOneAndUpdate({ email: id }, {email: req.body.email, password: req.body.password, nameOfUser: req.body.nameOfUser, surnameA: req.body.surnameA, surnameB: req.body.surnameB/*, status: false*/}, (err, userUpdate) => {
                    if(err){
                      return res.status(500).send({message: 'Error al actualizar los datos'});
                    }else{
                      if(!userUpdate){
                        return res.status(404).send({message: 'El dato no existe y no ha sido actualizado'});
                      }else{
                        //service_email.sendEmail(req.body.email);
                        token.tokenRenovation(req.body.email, userUpdate, nameOfOperation, res); //Guardar token en la base de datos
                      }
                    }
                  });
                });
              }else{
                User.findOneAndUpdate({ email: id }, {email: req.body.email, nameOfUser: req.body.nameOfUser, surnameA: req.body.surnameA, surnameB: req.body.surnameB/*, status: false*/}, (err, userUpdate) => {
                  if(err){
                    return res.status(500).send({ message: 'Error al actualizar los datos' });
                  }else{
                    if(!userUpdate){
                      return res.status(404).send({ message: 'El dato no existe y no ha sido actualizado' });
                    }else{
                      //service_email.sendEmail(req.body.email);
                      token.tokenRenovation(req.body.email, userUpdate, nameOfOperation, res); //Guardar token en la base de datos
                    }
                  }
                });
              }
          }else if(typeOfOperationOK == false){
              return res.status(404).send({ message: 'No tienes permisos para actualizar tus datos' });
          }else if(id != payload._id) {
              return res.status(404).send({ message: 'Los ID´s no coinciden' });
          }else if(req.body.dp){
              return res.status(404).send({ message: 'No puedes actualizar tus permisos' });
          }else if(req.body.hashX != hashX){
              return res.status(404).json({ message: 'HashX no coincide: '+hashX });
          }else{
              return res.status(404).json({ message: 'Errores en los datos typeOfOperationOK: '+typeOfOperationOK+' - initialToken (users): '+user.initialToken+' - Token (audit): '+auditData.Token+' - hashX (client): '+req.body.hashX+' - hashX(api): '+hashX });
          }
      })
      .catch(err => {
        // never goes here
        //console.log(err);
        return res.status(505).json({message: "Error 505 - typeOfOperationOK of dp"});
      });
    }/*else if(data.email == req.params.id.toLowerCase()){
      return res.status(200).json({ message: 'El email que ingresaste está asociado a tu cuenta, ingresa un nuevo email si requieres un cambio para este dato' });
    }*/else {
      return res.status(200).json({ message: 'Email en uso' });
    }
  })
  .catch(err => {
    // never goes here
    //console.log(err);
    return res.status(505).json({message: "Error 505 - data of email"});
  });
}

function userDelete(req, res) {
  var typeOfOperation = req.body.typeOfOperation;
  var nameOfOperation = req.body.nameOfOperation;
  var payload = service_jwt.decodeToken(req.headers.authorization);
  //console.log(payload);
  if(payload.life <= moment().unix()){
    return res.status(200).json({message: 'El token ha expirado: '+payload.life});
  }
  switch(typeOfOperation) {
    case 'delete':
      if(nameOfOperation == 'deleteRoot') {
        deleteRoot(req, res);
      }else if(nameOfOperation == 'deleteMe') {
        deleteMe(req, res);
      }else if(nameOfOperation == 'deleteAdministrator') {
        deleteAdministrator(req, res);
      }else if(nameOfOperation == 'deleteTUser') {
        deleteTUser(req, res);
      }
      break;
    default:
      return res.status(404).send({ message: 'Default case (userDelete) if exists a emergency' });
      break;
  }
}

function deleteRoot(req, res){
    var key = req.headers.authorization.replace(/['"]+/g, '');
    var typeOfOperation = req.body.typeOfOperation;
    var nameOfOperation = req.body.nameOfOperation;
    var query = { email: req.params.id.toLowerCase(), typeOfUser: 'Root' };
    //Pedir contraseña para confimar cambio
    Key.findOneAndRemove({ key: key }, (err, keyDelete) => {
        if(err){
            res.status(500).send({message: 'Error al eliminar los datos'});
        }else{
            if(!keyDelete){
                res.status(200).send({message: 'La llave no existe'});
            }else{
              User.findOneAndRemove(query, (err, userDelete) => {
                  if(err){
                      res.status(500).send({message: 'Error al eliminar los datos'});
                  }else{
                      if(!userDelete){
                          res.status(404).send({message: 'El dato no existe y no ha sido eliminado'});
                      }else{
                          token.tokenDelete(userDelete, nameOfOperation, res);
                      }
                  }
              });
            }
        }
    });
}

function deleteMe(req, res){
    var tokeninitial = req.headers.authorization;
    var typeOfOperation = req.body.typeOfOperation;
    var nameOfOperation = req.body.nameOfOperation;
    permit.hasAccess(tokeninitial, typeOfOperation, nameOfOperation)
    .then(typeOfOperationOK => {
        //console.log(typeOfOperationOK);
        tokeninitial.replace(/['"]+/g, '');
        //var payload = decodeToken(tokeninitial);
        var payload = service_jwt.decodeToken(tokeninitial);
        var id = req.params.id.toLowerCase(); //CAMBIAR ESTE DATO POR LA VARIABLE QUE CONTENDRÁ LOS ID's DE LOS USUARIOS REGISTRADOS
        var bool = false;
        if(typeOfOperationOK == true && id == payload._id && !req.body.email){
          count = false;
            //Pedir contraseña para confimar cambio
            User.findOneAndRemove({ email: id }, (err, userDelete) => {
                if(err){
                    res.status(500).send({message: 'Error al eliminar los datos'});
                }else{
                    if(!userDelete){
                        //res.status(404).send({message: 'El dato no existe y no ha sido eliminado'});
                        Consumer.findOneAndRemove({ email: id }, (err, userDelete) => {
                            if(err){
                                res.status(500).send({message: 'Error al eliminar los datos'});
                            }else{
                                if(!userDelete){
                                    res.status(404).send({message: 'El dato no existe y no ha sido eliminado'});
                                }else{
                                    //bool = true;
                                    //res.status(200).send({message: bool});
                                    token.tokenDelete(userDelete, nameOfOperation, res);
                                }
                            }
                        });
                    }else{
                        //bool = true;
                        //res.status(200).send({message: bool});
                        token.tokenDelete(userDelete, nameOfOperation, res);

                    }
                }
            });
        }else if(typeOfOperationOK == false){
            res.status(404).send({message: 'No tienes permisos para eliminar tus datos'});
        }else if(id != payload._id) {
            res.status(404).send({message: 'Los ID´s no coinciden'});
        }else if(req.body.email){
            res.status(404).send({message: 'No puedes eliminar tu email - contacta con el desarrollador'});
        }else{
            res.status(404).send({message: 'Errores en los datos typeOfOperationOK: '+typeOfOperationOK+' - ID (users) : '+id +' - ID (token): '+payload._id+' - Email: '+req.body.email });
        }
    })
    .catch(err => {
        // never goes here
        //console.log(err);
        return res.status(550).json(err);
    });
}

function deleteAdministrator(req, res){
    var tokeninitial = req.headers.authorization;
    var typeOfOperation = req.body.typeOfOperation;
    var nameOfOperation = req.body.nameOfOperation;
    permit.hasAccess(tokeninitial, typeOfOperation, nameOfOperation)
    .then(typeOfOperationOK => {
        var id = req.params.id.toLowerCase(); //CAMBIAR ESTE DATO POR LA VARIABLE QUE CONTENDRÁ LOS ID's DE LOS USUARIOS REGISTRADOS
        var bool = false;
        var query = { email: id, typeOfUser: 'Administrator' };
        User.findOne(query, (err, usersStored) => {
            if(err) {
                res.status(500).send({message: 'Error en la petición'});
            }else {
                if(!usersStored) {
                    res.status(404).send({message: 'No se ha encontrado el dato'});
                }else {
                    if(typeOfOperationOK == true && !req.body.email){
                        //Pedir contraseña para confimar cambio
                            User.findOneAndRemove({ email: id }, (err, userDelete) => {
                                if(err){
                                    res.status(500).send({message: 'Error al eliminar los datos'});
                                }else{
                                    if(!userDelete){
                                        res.status(404).send({message: 'El dato no existe y no ha sido eliminado'});
                                    }else{
                                        //bool = true;
                                        //res.status(200).send({message: bool});
                                        token.tokenDelete(userDelete, nameOfOperation, res);
                                    }
                                }
                            });
                    }else if(typeOfOperationOK == false){
                        res.status(404).send({message: 'No tienes permisos para eliminar administradores'});
                    }else if(req.body.email){
                        res.status(404).send({message: 'No puedes eliminar el email - contacta con el desarrollador'});
                    }else{
                        res.status(404).send({ message: 'Errores en los datos typeOfOperationOK: '+typeOfOperationOK+' - ID (users) : '+id +' - ID (token): '+payload._id+' - Email: '+req.body.email });
                    }
                }
            }
        });
    });
}

function deleteTUser(req, res){
    var tokeninitial = req.headers.authorization;
    var typeOfOperation = req.body.typeOfOperation;
    var nameOfOperation = req.body.nameOfOperation;
    permit.hasAccess(tokeninitial, typeOfOperation, nameOfOperation)
    .then(typeOfOperationOK => {
        var id = req.params.id.toLowerCase(); //CAMBIAR ESTE DATO POR LA VARIABLE QUE CONTENDRÁ LOS ID's DE LOS USUARIOS REGISTRADOS
        var bool = false;
        //var query = { email: id, typeOfUser: 'TUser' };
        var query = { email: id };
        if(typeOfOperationOK == true && !req.body.email){
            //Pedir contraseña para confimar cambio
            User.findOneAndRemove({ email: id }, (err, userDelete) => {
                if(err){
                    res.status(500).send({message: 'Error al eliminar los datos'});
                }else{
                    if(!userDelete){
                        res.status(404).send({message: 'El dato no existe y no ha sido eliminado'});
                    }else{
                        //bool = true;
                        //res.status(200).send({message: bool});
                        token.tokenDelete(userDelete, nameOfOperation, res);
                    }
                }
            });
        }else if(typeOfOperationOK == false){
            res.status(404).send({message: 'No tienes permisos para eliminar usuarios normales'});
        }else if(req.body.email){
            res.status(404).send({message: 'No puedes eliminar el email - contacta con el desarrollador'});
        }else{
            res.status(404).send({ message: 'Errores en los datos typeOfOperationOK: '+typeOfOperationOK+' - ID (users) : '+id +' - ID (token): '+payload._id+' - Email: '+req.body.email });
        }
    });
}

function getUser(req, res){
    var userId = req.params.id;
    var token = req.headers.authorization;
    var payload = service_jwt.decodeToken(token);
    var typeOfOperation = 'read';
    var nameOfOperation;
    User.findOne({email: userId}, (err, user) => {
        if(err){
            res.status(500).send({message: 'Error en la petición'});
        }else{
            if(!user){
                res.status(404).send({message: 'El dato no existe'});
            }else{
                if(payload._id == req.params.id){
                    nameOfOperation = 'readMe';
                }else if(user.typeOfUser == 'Administrator') {
                    nameOfOperation = 'readAdministrator';
                }else {
                    nameOfOperation = 'readTUser';
                }
                permit.hasAccess(token, typeOfOperation, nameOfOperation) //Antes de verificar los permisos verificar el dueño del token
                .then(typeOfOperationOK => {
                    //console.log(typeOfOperationOK);
                    if(typeOfOperationOK == true){
                        res.status(200).send({ user });
                    }else{
                        res.status(404).send({message: 'No tienes permisos para ver estos datos'});
                    }
                })
                .catch(err => {
                    // never goes here
                    //console.log(err);
                    return res.status(550).json(err);
                });
            }
        }
    });
}

function getUsers(req, res){
    var payload = service_jwt.decodeToken(req.headers.authorization);
    if(req.params.page){
        var page = req.params.page;
    }else{
        var page = 1;
    }
    var itemsPerPage = 5;
    User.find().sort('email').paginate(page, itemsPerPage, function(err, users, total){
        if(err){
            res.status(500).send({message: 'Error en la petición'});
        }else{
            if(!users){
                res.status(404).send({message: 'No hay datos'});
            }else{
                if(payload.typeOfUser == 'Root' || payload.typeOfUser == 'Administrator'){
                    var token = req.headers.authorization;
                    var typeOfOperation = 'read';
                    var nameOfOperation = 'readAdministrator';
                    var usersView = [];
                    permit.hasAccess(token, typeOfOperation, nameOfOperation)
                    .then(typeOfOperationOK => {
                        if(typeOfOperationOK == true){
                            for(var user of users){
                                if(user.typeOfUser == 'Administrator' && user.email != payload._id){
                                    usersView.push(user);
                                }
                            }
                        }
                        nameOfOperation = 'readTUser';
                        permit.hasAccess(token, typeOfOperation, nameOfOperation)
                        .then(typeOfOperationOK => {
                            if(typeOfOperationOK == true){
                                for(var user of users){
                                    if(user.typeOfUser == 'TUser' || user.typeOfUser == 'Merchant' || user.typeOfUser == 'Carrier' || user.typeOfUser == 'Acopio' || user.typeOfUser == 'Productor'){
                                        usersView.push(user);
                                    }
                                }
                            }
                            //console.log(usersView);
                            return res.status(200).send({ total_items: total, users: usersView });
                        })
                        .catch(err => {
                            // never goes here
                            //console.log(err);
                            return res.status(550).json(err);
                        });
                    })
                    .catch(err => {
                        // never goes here
                        //console.log(err);
                        return res.status(550).json(err);
                    });
                 }else{
                     return res.status(400).send({ message: 'No tienes permisos para ver datos de otros usuarios' });
                 }
             }
         }
    });
}

function emailToReset(req, res) {
  User.findOne({email: req.body.email}, (err, data) => {
    if(err){
      res.status(500).send({message: 'Error en la petición'});
    }else{
      if(!data){
        res.status(404).send({message: 'El email no existe'});
      }else{
        Confirmation.findOne({ email: req.body.email }, (err, confirmationStored) => {
          if(err){
            res.status(500).send({message: 'Error al eliminar los datos'});
          }else{
            if(!confirmationStored){
              service_email.sendEmailToResetPassword(req.body.email);
              res.status(200).send({message: 'Se te ha enviado un email para restaurar tu contraseña'});
            }else{
              res.status(200).send({message: 'Ya se te ha enviado un email para restaurar tu contraseña'});
            }
          }
        });
      }
    }
  });
}

/*
function registerUser(req, res){
    var email = req.body.email;
    User.findOne({email: email.toLowerCase()}, (err, emailStored) => {
        if(err){
            res.status(500).send({ message: 'Error en la petición' });
        }else{
            if(!emailStored){
                var ip = req.header('x-forwarded-for') || req.connection.remoteAddress;
                var dp = '{ "createAdministrator": '+false+', "createTUser": '+false+', "updateMe": '+true+', "updateAdministrator": '+false+', "updateTUser": '+false+', "deleteMe": '+true+', "deleteAdministrator": '+false+', "deleteTUser": '+false+', "readMe": '+true+', "readAdministrator": '+false+', "readTUser": '+false+', "loginUser": '+true+' }';
                var user = new User();

                user.email = req.body.email.toLowerCase();
                user.password = req.body.password;
                user.nameOfUser = req.body.nameOfUser;
                user.surnameP = req.body.surnameP;
                user.surnameM = req.body.surnameM;
                user.ip = ip;
                user.typeOfUser = 'Consumer';
                user.dp = dp;
                if(req.body.password){
                    //Encriptar contraseñas
                    bcrypt.hash(req.body.password, null, null, function(err, hash){
                        user.password = hash;
                        if(user.email != null && user.password != null && user.nameOfUser != null && user.surnameM != null && user.surnameM != null){
                            //Guardar usuario
                            user.save((err, userStored) => {
                                if(err) {
                                    console.log(err);
                                    res.status(500).json({ message: 'Error al guardar los datos' });
                                }else {
                                    if(!userStored) {
                                        res.status(404).json({ message: 'El dato no ha sido guardado' });
                                    }else {
                                        var generatedToken = service_jwt.createToken(user); //Guardar token en la base de datos
                                        token.tokenCreation(generatedToken, user.email);
                                        req.body.typeOfOperation = 'authentication';
                                        req.body.nameOfOperation = 'loginUser';
                                        service_email.sendEmail(email);
                                        token.authenticateConsumers(req, res);
                                    }
                                }
                            });
                        }else {
                            res.status(200).json({ message: 'Rellena todos los campos' });
                        }
                    });
                }else {
                    res.status(200).json({ message: 'Introduce la contraseña' });
                }
            }else{
                console.log("Entré aquí - "+emailStored);
                res.status(404).send({ message: 'Ya existe un usuario con el email: '+email });
            }
        }
    });

}
*/

/*
function deleteConsumer(req, res){
    var tokeninitial = req.headers.authorization;
    var typeOfOperation = req.body.typeOfOperation;
    var nameOfOperation = req.body.nameOfOperation;
    permit.hasAccess(tokeninitial, typeOfOperation, nameOfOperation)
    .then(typeOfOperationOK => {
        //console.log(typeOfOperationOK);
        tokeninitial.replace(/['"]+/g, '');
        //var payload = decodeToken(tokeninitial);
        var payload = service_jwt.decodeToken(tokeninitial);
        var id = req.params.id.toLowerCase(); //CAMBIAR ESTE DATO POR LA VARIABLE QUE CONTENDRÁ LOS ID's DE LOS USUARIOS REGISTRADOS
        var bool = false;
        if(typeOfOperationOK == true && id == payload._id && !req.body.email){
            //Pedir contraseña para confimar cambio
            Consumer.findOneAndRemove({ email: id }, (err, userDelete) => {
                    if(err){
                        res.status(500).send({message: 'Error al actualizar los datos'});
                    }else{
                        if(!userDelete){
                            res.status(404).send({message: 'El dato no existe y no ha sido actualizado'});
                        }else{
                            bool = true;
                            res.status(200).send({message: bool});
                        }
                    }
                });
        }else if(typeOfOperationOK == false){
            res.status(404).send({message: 'No tienes permisos para eliminar tus datos'});
        }else if(id != payload._id) {
            res.status(404).send({message: 'Los ID´s no coinciden'});
        }else if(req.body.email){
            res.status(404).send({message: 'No puedes actualizar tu email - contacta con el desarrollador'});
        }else{
            res.status(404).send({ message: 'Errores en los datos typeOfOperationOK: '+typeOfOperationOK+' - ID (users) : '+id +' - ID (token): '+payload._id+' - Email: '+req.body.email });
        }
    })
    .catch(err => {
        // never goes here
        console.log(err);
        return res.status(550).json(err);
    });
}
*/

//--------------------------------------------New--------------------------------------------

module.exports = {
    userCreate,
    userUpdate,
    userDelete,
    emailToReset,
    getUser,
    getUsers,
    //registerUser
};
