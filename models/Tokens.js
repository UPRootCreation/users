var mongoose = require('mongoose');
var Schema = mongoose.Schema;

var TokenSchema = new Schema({
    email: {type: String, required: true, max: 100},
    generatedToken: {type: String, required: true, max: 5000}
});

module.exports = mongoose.model('Token', TokenSchema);
