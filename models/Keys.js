var mongoose = require('mongoose');
var Schema = mongoose.Schema;

var KeySchema = new Schema({
    key: {type: String, required: true, max: 100}
});

module.exports = mongoose.model('Key', KeySchema);
