//
var User = require('../models/Users');
var Session = require('../models/Sessions');
var Key = require('../models/Keys');
var axios = require('axios');
var bcrypt = require('bcrypt-nodejs');
var md5 = require('md5');

var service_jwt = require('../services/jwt');
var token = require('./token');

var d = new Date();

//--------------------------------------------New--------------------------------------------
function userCreate(req, res) {
  switch(req.body.typeOfUser.toLowerCase()){
    case 'root':
      var body = {
        email: req.body.email,
        password: req.body.password,
        surnameA: req.body.surnameA,
        surnameB: req.body.surnameB,
        addressU: req.body.addressU
      };
      console.log('<-- Date: '+d.getFullYear()+'-'+d.getMonth()+'-'+d.getDay()+' '+d.getHours()+':'+d.getMinutes()+':'+d.getSeconds()+':'+d.getMilliseconds()+'; Body - data: '+JSON.stringify(body)+'; Headers - A: '+req.headers.session.replace(/['"]+/g, '')+'; Headers - token: '+req.headers.authorization.replace(/['"]+/g, '')+'');
      checkRoot(req, res);
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
        //console.log("checkRoot");
        count = true;
        console.log('--> Date: '+d.getFullYear()+'-'+d.getMonth()+'-'+d.getDay()+' '+d.getHours()+':'+d.getMinutes()+':'+d.getSeconds()+':'+d.getMilliseconds()+'; message: deny; A: '+req.headers.session.replace(/['"]+/g, '')+'; token: '+req.headers.authorization.replace(/['"]+/g, '')+'');
        res.status(200).send({ message: 'deny', A: req.headers.session.replace(/['"]+/g, ''), token: req.headers.authorization.replace(/['"]+/g, '')});
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
          default:
            res.status(404).send({ message: 'Default case (checkEmail) if exists a emergency' });
            break;
        }
      }else{
        count = true;
        res.status(404).send({ message: 'Ya existe un usuario con el email: '+email });
      }
    }
  });
}

function createRoot(req, res){
  var ip = req.header('x-forwarded-for') || req.connection.remoteAddress;
  var query = { sessionID: req.headers.session.replace(/['"]+/g, ''), token: req.headers.authorization.replace(/['"]+/g, '') };
	Session.findOne(query, (err, sessionStored) => {
		if(err){
			res.status(500).send({message: 'Error en la petición'});
		}else{
			if(!sessionStored){
        //console.log("sessionStored");
        console.log('--> Date: '+d.getFullYear()+'-'+d.getMonth()+'-'+d.getDay()+' '+d.getHours()+':'+d.getMinutes()+':'+d.getSeconds()+':'+d.getMilliseconds()+'; message: deny; A: '+req.headers.session.replace(/['"]+/g, '')+'; token: '+req.headers.authorization.replace(/['"]+/g, '')+'');
        res.status(200).send({message: 'deny', A: req.headers.session.replace(/['"]+/g, ''), token: req.headers.authorization.replace(/['"]+/g, '')});
			}else{
        //Count is a global var
        if (count == false) {
          count = true;
          serviceInit(req, req.headers.authorization, function(data, err) {
            if (err) {
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
              user.addressContract =  auditData.Atr;
              user.addressTransaction = auditData.Asc;
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
              var hashX = md5(JSON.stringify(jsonData));
              if(user.initialToken == auditData.To && req.body.hashX == hashX && countTwo == false){
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
              }else if(user.initialToken != auditData.To){
                res.status(401).send({ message: 'Errores en los datos initialToken (users): '+user.initialToken+' - Token (audit): '+auditData.To });
              }else if(req.body.hashX != hashX){
                res.status(401).json({ message: 'Errores en los datos hashX (client): '+req.body.hashX+' - hashX(api): '+hashX });
              }else if (countTwo == true) {
                res.status(401).json({ message: 'Ha sucedido algo inesperado, intenta nuevamente pero hice la petición a audit' });
              }
            }
          });
        }else if (count == true) {
          //console.log("count");
          console.log('--> Date: '+d.getFullYear()+'-'+d.getMonth()+'-'+d.getDay()+' '+d.getHours()+':'+d.getMinutes()+':'+d.getSeconds()+':'+d.getMilliseconds()+'; message: deny; A: '+req.headers.session.replace(/['"]+/g, '')+'; token: '+req.headers.authorization.replace(/['"]+/g, '')+'');
          res.status(200).send({message: 'deny', A: req.headers.session.replace(/['"]+/g, ''), token: req.headers.authorization.replace(/['"]+/g, '')});
          //res.status(401).json({ message: 'Ha sucedido algo inesperado, intenta nuevamente' });
        }
			}
		}
	});
}

function serviceInit(req, initialToken, next) {
    var source = req.header('x-forwarded-for') || req.connection.remoteAddress;
    var target = 'Audit Server';
    var data = { user: req.body.email, pass: req.body.password };
    var keyR = req.body.addressU;
    var To = req.headers.authorization;
    var data;
    var url = 'http://'+host+':'+port.audit+''+path.audit+'';
    axios.post(url, {
        source: source,
        target: target,
        data: data,
        keyR: keyR,
        To: To
    })
    .then(response => {
        data = response.data;
        next(data, null);
    })
    .catch(error => {
        next(null, error);
    });
}

module.exports = {
    userCreate
};
