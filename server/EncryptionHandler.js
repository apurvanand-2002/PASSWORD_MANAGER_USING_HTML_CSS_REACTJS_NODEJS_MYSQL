const crypto = require("crypto");
/* 'crypto' is an inbuilt module.*/
const secret = "pppppppppppppppppppppppppppppppp";

/*'Buffer' refers to particular memory location in the memory. A buffer can contain only
 binary data and it can not contain any other 'datatype' and buffer can not be resized.
 So, as buffer is in 'binary' form and it is not a string but a 'memory location' , for 
 returning it from the functions below we need to first, convert it to string and that
too in 'hexadecimal' form.*/
const encrypt = (password) => {
    /* generating our identifier*/
    const iv = Buffer.from(crypto.randomBytes(16));
    /*For each encryption, we will need an identifier. Above line generates a 16 byte 
    identifier. 'randomBytes' will make random identifier each time.*/
    const cipher = crypto.createCipheriv("aes-256-ctr", Buffer.from(secret), iv);
    /*'aes-256-ctr' is an encrypting algorithm. The second arguement generates the 16 byte
    buffer from 'secret'. 'iv' is an identifier.*/
    /*'cipher' will be used for enncrypting our passwords.*/
    const encryptedPassword = Buffer.concat([
        cipher.update(password),
        /*cipher.update(password) -used to update password based on 'cipher'*/
        cipher.final()
        /*cipher.final() -adds some final digits from cipher obtained.*/
        /*As we do not know 'iv' as it is generated randomly, also other won't know
        ones secret and if other knows also, the other won't be able to predict the
        16 random bytes generated from the 'secret', hence, our method has very high
        security.*/
    ])
    return { iv: iv.toString("hex"), password: encryptedPassword.toString("hex") };
}

const decrypt = (encryption) => {
    const decipher = crypto.createDecipheriv("aes-256-ctr", Buffer.from(secret), Buffer.from(encryption.iv, "hex"))
    const decryptedPassword = Buffer.concat([
        decipher.update(Buffer.from(encryption.password, "hex")),
        decipher.final(),
    ])
    return decryptedPassword.toString();
}

module.exports = { encrypt, decrypt };