var path = require('path');
var express = require('express');
var crypto = require('crypto');
var md5 = require('md5');

var Session = require("../models/Sessions");
var User = require("../models/Users");
var router = express.Router();

var UserController = require('../controller/user');
var TokenController = require('../controller/token');

/*----------Pruebas de conexión y obtención de datos----------*/
router.get('/', function(req, res){
	res.render('index');
});

//rootCreation
router.post('/getInitialNonce', function (req, res) {
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
});
router.post('/userCreation', UserController.userCreate);
router.post('/login', TokenController.authenticate);

/*----------Pruebas de conexión y obtención de datos----------*/

module.exports = router;
