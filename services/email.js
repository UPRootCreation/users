var Confirmation = require('../models/Confirmations');
var User = require('../models/Users');
var token = require('../controller/token');

var nodemailer = require('nodemailer');
var bcrypt = require('bcrypt-nodejs');
var moment = require('moment');

function sendEmail(email){
  var confirmation = new Confirmation();
  var code = null;
    bcrypt.hash(email, null, null, function(err, hash){
        code = hash;
        var transporter = nodemailer.createTransport({
            service: 'gmail',
            port: 587,
            secure: false, // true for 465, false for other ports
            auth: {
                user: 'avocadopath@gmail.com',
                pass: 'Avocado321_'
            }
        });

        var mailOptions = {
            from: 'avocadopath@gmail.com',
            to: email,
            subject: 'Email confirmation - AvocadoPath',
            text: 'Please click: http://52.202.214.13/verifyEmail/?code='+code+'&email='+email+''
        };

        transporter.sendMail(mailOptions, function(error, info){
            if (error) {
                console.log(error);
            } else {
                confirmation.email = email;
                confirmation.code = code;
                confirmation.creation = moment().unix(); //Momento de creación (fecha y hora exacta)
                confirmation.life = moment().add(30, 'm').unix(); //Agrega 30 minutos en tiempo UNIX
                confirmation.save((err, confirmationStored) => {
                    if(err) {
                        console.log('message: Error al guardar los datos');
                    }else{
                        if(!confirmationStored) {
                        console.log('message: El dato no ha sido guardado');
                        }else{
                        console.log(confirmationStored);
                        return confirmationStored;
                        }
                    }
                });
            }
        });
    });
}

function sendEmailToResetPassword(email){
    var confirmation = new Confirmation();
    var code = null;
    bcrypt.hash(email, null, null, function(err, hash){
        code = hash;
        var transporter = nodemailer.createTransport({
            service: 'gmail',
            port: 587,
            secure: false, // true for 465, false for other ports
            auth: {
                user: 'avocadopath@gmail.com',
                pass: 'Avocado321_'
            }
        });

        var mailOptions = {
            from: 'pruebas.postman.residencia@gmail.com',
            to: email,
            subject: 'Reset password - AvocadoPath',
            text: 'Please click: http://52.202.214.13/resetPassword/?code='+code+'&email='+email+''
        };
        transporter.sendMail(mailOptions, function(error, info){
            if (error) {
                console.log(error);
            } else {
                confirmation.email = email;
                confirmation.code = code;
                confirmation.creation = moment().unix(); //Momento de creación (fecha y hora exacta)
                confirmation.life = moment().add(30, 'm').unix(); //Agrega 30 minutos en tiempo UNIX
                confirmation.save((err, confirmationStored) => {
                    if(err) {
                        console.log('message: Error al guardar los datos');
                    }else{
                        if(!confirmationStored) {
                        console.log('message: El dato no ha sido guardado');
                        }else{
                        console.log(confirmationStored);
                        return confirmationStored;
                        }
                    }
                });
            }
        });
    });
}

function checkConfirmations(email) {
  return new Promise(function(resolve, reject) {
    Confirmation.findOne({ email: email })
    .then(confirmationStored => {
      if(!confirmationStored){
        resolve(false);
      }else{
        resolve(true);
      }
    })
    .then(undefined, function(err){
			reject(err);
		});
  });
}

function verifyEmail(req, res){
  var id = req.query.code;
  var email = req.query.email;
  checkConfirmations(email)
  .then(data => {
    if (data == true) {
      Confirmation.findOneAndRemove({ email: email, code: id }, (err, confirmationDelete) => {
        if(err){
          res.status(500).send({message: 'Error al eliminar los datos'});
        }else{
          if(!confirmationDelete){
            res.status(200).send({message: 'El dato no existe'});
          }else{
            if(confirmationDelete.life <= moment().unix()){
              return res.status(200).json({message: "El enlace ha expirado: "+confirmationDelete.life});
            }
            User.findOneAndUpdate({ email: email, typeOfUser: 'Consumer' }, {status: data}, (err, userUpdate) => {
              if(err){
                res.status(500).send({message: 'Error al actualizar los datos'});
              }else{
                if(!userUpdate){
                  res.status(404).send({message: 'El dato no existe y no ha sido actualizado'});
                }else{
                  res.status(200).send({message: data});
                }
              }
            });
          }
        }
      });
    }else {
      res.status(200).send({message: 'La petición no existe'});
      //return data;
    }
  })
  .catch(err => {
    // never goes here
    //console.log(err);
    return res.status(505).json({message: "Error 505"});
  });
}

function resetPasswordGET(req, res){
  checkConfirmations(req.query.email)
  .then(data => {
    if (data == true) {
      res.status(200).send({message: data});
    }else {
      res.status(200).send({message: data});
    }
  })
  .catch(err => {
    //console.log(err);
    return res.status(505).json({message: "Error 505"});
  });
}

function resetPasswordPUT(req, res){
  if(req.body.password != req.body.password_confirmation){
    return res.status(200).json({message: "Las contraseñas no coinciden"});
  }else if (req.body.password == null || req.body.password == '') {
    return res.status(200).send({message: 'La contraseña no puede estar vacía'});
  }
  var id = req.query.code;
  var email = req.query.email;
  checkConfirmations(email)
  .then(data => {
    if (data == true) {
      Confirmation.findOneAndRemove({ email: email, code: id }, (err, confirmationDelete) => {
        if(err){
          res.status(500).send({message: 'Error al eliminar los datos'});
        }else{
          if(!confirmationDelete){
            res.status(200).send({message: 'El dato no existe'});
          }else{
            if(confirmationDelete.life <= moment().unix()){
              return res.status(200).json({message: "El enlace ha expirado. Ya no podrás usar este enlace. "+confirmationDelete.life});
            }
            bcrypt.hash(req.body.password, null, null, function(err, hash){
              req.body.password = hash;
              User.findOneAndUpdate({ email: email, typeOfUser: 'Consumer' }, {password: req.body.password}, (err, userUpdate) => {
                if(err){
                  res.status(500).send({message: 'Error al actualizar los datos'});
                }else{
                  if(!userUpdate){
                    res.status(404).send({message: 'El dato no existe y no ha sido actualizado'});
                  }else{
                    token.tokenRenovation(email, userUpdate, 'resetPassword', res); //Guardar token en la base de datos
                  }
                }
              });
            });
          }
        }
      });
    }else {
      res.status(200).send({message: 'La petición no existe'});
      //return data;
    }
  })
  .catch(err => {
    // never goes here
    //console.log(err);
    return res.status(505).json({message: "Error 505"});
  });
}

module.exports = {
  sendEmail,
  sendEmailToResetPassword,
  verifyEmail,
  resetPasswordGET,
  resetPasswordPUT
};
