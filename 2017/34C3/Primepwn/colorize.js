// connect to http://ref.x86asm.net/coder64.html

function convert(elem) {
    return parseInt(elem);
}

function isPrime(value) {
    for(var i = 2; i < value; i++) {
        if(value % i === 0) {
            return false;
        }
    }
    return value > 1;
}


$('tbody').each(function(){
    var elem=$(this).attr("id")
    if (typeof elem === "string") {
        elem="0"+elem;
        var conv=convert(elem);
        //console.log("0"+elem)
        if(isPrime(conv)) {
            console.log(conv)
        }
    }
})
