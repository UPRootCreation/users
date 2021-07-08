var path = require('path');
var express = require('express');
var jwt = require('jwt-simple');
var moment = require('moment');
var crypto = require('crypto');
var fs = require('fs');
var md5 = require('md5');


var md_auth = require('../middlewares/authenticated');
var Session = require("../models/Sessions");
var User = require("../models/Users");
var service_jwt = require('../services/jwt');
var router = express.Router();

//var main = require('../controller/index.js');
//var modelRoot = require('../controller/modelRoot.js');
var userCreation = require('../controller/userCreation.js');
//var restAdmor = require('../controller/restAdmor.js');
//var restToken = require('../controller/restToken.js');
var sbi = require('../controller/sbi.js');
//var us = require('../controller/users.js');

//var root = require('../controller/root.js');

var UserController = require('../controller/user');
var TokenController = require('../controller/token');
var PermitController = require('../controller/permit');
var TransactionController = require('../controller/transaction');
var EmailController = require('../services/email');


//************************************************
//************************************************
//ROUTES FOR RESTFUL REQUESTS
//************************************************
//TOKEN
//************************************************
//router.post('/exec/getToken', restToken.createToken);
//router.post('/exec/isValid', restToken.isValid); //not token public is available
//router.post('/exec/who', restToken.who); //not token public is available
//************************************************

//ROOT
router.post('/exec/rootConstructor', userCreation.createUser);
//router.post('/exec/getAddContrR', userCreation.getAddContrR);
//router.post('/exec/getAddTransR', userCreation.getAddTransR);
//************************************************
//ADMINISTRATOR
//router.post('/exec/admorConstructor', restAdmor.createAdmor);
//router.post('/exec/getAddContrR', restRoot.getAddContrR);
//router.post('/exec/getAddTransR', restRoot.getAddTransR);
//************************************************


//SBI
router.post('/exec/permit', sbi.permit);
//router.post('/exec/getAddContrR', restRoot.getAddContrR);
//router.post('/exec/getAddTransR', restRoot.getAddTransR);
//************************************************
//************************************************

/*----------Pruebas de conexión y obtención de datos----------*/
router.get('/', function(req, res){
	res.render('index');
});

//userCreation
router.post('/getInitialNonce', function (req, res) {
	setTimeout(() => {
		User.findOne({ typeOfUser: 'Root' }, (err, userStored) => {
				if(err) {
						res.status(500).send({ message: 'Error en la petición' });
				}else {
						if(!userStored) {
							var session = new Session();
							var md5sum = crypto.createHash('md5');
							session.sessionID = req.body.session; // A
							session.na = req.body.na; // Na
							session.nb = crypto.randomBytes(16).toString('base64'); // Nb
							//session.token = md5sum.update(session.na+session.nb).digest('hex'); // token = hash(Na, Nb)
							session.token = md5(JSON.stringify(session.na+session.nb));
							session.save((err, sessionStored) => {
								if(err) {
									res.status(500).send({ message: 'Error al guardar los datos' });
								}else{
									if(!sessionStored) {
										res.status(404).send({ message: 'El dato no ha sido guardado' });
									}else{
										//console.log(sessionStored);
										var d = new Date();
										console.log('Date: '+d+'; A: '+sessionStored.sessionID+'; NA: '+sessionStored.na+'; NB: '+sessionStored.nb+'');
										res.status(200).send({ A: sessionStored.sessionID, NA: sessionStored.na, NB: sessionStored.nb });
									}
								}
							});
						}else {
							var d = new Date();
							console.log('Date: '+d+'; message: deny; A: '+req.body.session+'; NA: '+req.body.na+'');
							res.status(200).send({ message: 'deny', A: req.body.session, NA: req.body.na });
							//res.status(404).send({ message: "Ya existe un usario Root, no puedes crear más" });
							//res.status(200).send({ message: false, A: req.body.session, na: req.body.na /*, message: "Ya existe un usario Root"*/ });
						}
				}
		});
	}, 1000);
});
/*router.post('/userCreation', function(req, res){
  UserController.userCreation
});
router.put('/userUpdate/:id', function(req, res){
  UserController.userUpdate
});
router.delete('/userDelete/:id', function(req, res){
  UserController.userDelete
});
router.post('/login', function(req, res){
  UserController.loginUser
});*/
router.get('/userDetails/:id', UserController.getUser);
router.get('/usersDetails/:page?', UserController.getUsers);
router.post('/userCreation', UserController.userCreate);
router.post('/emailToReset', UserController.emailToReset);

//router.post('/register', UserController.registerUser); //Consumer
router.put('/userUpdate/:id', UserController.userUpdate);
router.delete('/userDelete/:id', UserController.userDelete);

//Authentication
//router.get('/getInitialToken', TokenController.getInitialToken(req, res, booleanToken));
router.post('/login', TokenController.authenticate);
//router.post('/login/token', TokenController.checkTokens);
router.put('/tokenRenovation', TokenController.tokenRenovation);
router.post('/tokenIsValid', TokenController.tokenIsValid);

//Permit
/*router.get('/permitions', function(req, res){
	res.render('permitions');
});*/
router.get('/permitions', PermitController.permitions);

//Merchant
router.post('/merchantData', TransactionController.merchantData);

//Email
router.get('/verifyEmail', EmailController.verifyEmail);
router.get('/resetPassword', EmailController.resetPasswordGET);
router.put('/resetPassword', EmailController.resetPasswordPUT);

//router.post('/sendEmail', EmailController.sendEmail);
/*----------Pruebas de conexión y obtención de datos----------*/

module.exports = router;
