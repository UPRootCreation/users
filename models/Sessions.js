var mongoose = require('mongoose');
var Schema = mongoose.Schema;

var SessionSchema = Schema({
    sessionID: {type: String, required: true, max: 100},
    na: {type: String, required: true, max: 100},
    nb: {type: String, required: true, max: 100},
    token: {type: String, required: true, max: 100}
});

module.exports = mongoose.model('Session', SessionSchema);
