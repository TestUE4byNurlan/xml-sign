var forge = require('node-forge');
var select = require('xml-crypto').xpath,
    dom = require('xmldom').DOMParser,
    SignedXml = require('xml-crypto').SignedXml,
    FileKeyInfo = require('xml-crypto').FileKeyInfo,
    fs = require('fs'),
    xpath = require('xpath');
const { Certificate } = require('@fidm/x509')
const http = require('http');
const readline = require('readline');
const stream = require('stream');
const Cg = require('./app-config.js');
const dqueries = require('./db-queries.js');
const forceSync = require('sync-rpc')

function SignKeyInfo(prefix) {
    this.getKeyInfo = function(key, prefix) {
        prefix = prefix || ''
        prefix = prefix ? prefix + ':' : prefix
        return "<" + prefix + "X509Data><" + prefix + "X509Certificate>" +
            removeHeaderFromPem(forge.pki.certificateToPem(cert)) +
            "</" + prefix + "X509Certificate></" + prefix + "X509Data>"
    }
    this.getKey = function(keyInfo) {
        //you can use the keyInfo parameter to extract the key in any way you want       
        return forge.pki.privateKeyToPem(privateKey)
    }
}

function derToPem(der) {
    let derKey = forge.util.decode64(der);
    let asnObj = forge.asn1.fromDer(derKey);
    let asn1Cert = forge.pki.certificateFromAsn1(asnObj);
    return forge.pki.certificateToPem(asn1Cert);
};

function ValidateKeyInfo(key, prefix) {
    this.getKeyInfo = function(key, prefix) {
        prefix = prefix || ''
        prefix = prefix ? prefix + ':' : prefix
        return "<" + prefix + "X509Data><" + prefix + "X509Certificate>" +
            removeHeaderFromPem(key) +
            //  removeHeaderFromPem(forge.pki.certificateToPem(cert)) +
            "</" + prefix + "X509Certificate></" + prefix + "X509Data>"
    }

    this.getKey = function(keyInfo) {
        return key;
        //  return forge.pki.certificateToPem(cert)
    }

}

function removeHeaderFromPem(pem) {
    let lines = pem.split('\n');
    let encoded = '';
    for (let i = 0; i < lines.length; i++) {
        if (lines[i].trim().length > 0 &&
            lines[i].indexOf('-BEGIN CERTIFICATE-') < 0 &&
            lines[i].indexOf('-BEGIN RSA PRIVATE KEY-') < 0 &&
            lines[i].indexOf('-BEGIN RSA PUBLIC KEY-') < 0 &&
            lines[i].indexOf('-BEGIN PUBLIC KEY-') < 0 &&
            lines[i].indexOf('-END CERTIFICATE-') < 0 &&
            lines[i].indexOf('-END PUBLIC KEY-') < 0 &&
            lines[i].indexOf('-END RSA PRIVATE KEY-') < 0 &&
            lines[i].indexOf('-END RSA PUBLIC KEY-') < 0) {
            encoded += lines[i].trim();
        }
    }
    return encoded;
}


function signXml(xml, xpath, key, dest) {
  //  var option = { implicitTransforms: ["http://www.w3.org/TR/2001/REC-xml-c14n-20010315"] }
    var sig = new SignedXml();
    //sig.signingKey = fs.readFileSync(key)
    sig.signingKey = key
    const args = ["http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"];
    sig.addReference(xpath, [["http://www.w3.org/2000/09/xmldsig#enveloped-signature"],["http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"]], "http://www.w3.org/2001/04/xmlenc#sha256");
    sig.signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    sig.canonicalizationAlgorithm = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
 //   fs.writeFileSync('signed sig.xml', JSON.stringify(sig));
    sig.keyInfoProvider = new SignKeyInfo('ds')
    sig.computeSignature(xml, {
        prefix: 'ds'
    })
    fs.writeFileSync(dest, sig.getSignedXml())
}


function getFilesizeInBytes(filename) {
    const stats = fs.statSync(filename);
    const fileSizeInBytes = stats.size;
    return fileSizeInBytes;
}


/* /////другие варианты скачивания и выполнения 
var request = http.get('http://crl.pki.gov.kz/nca_d_rsa.crl', function(response) {
    if (response.statusCode === 200) {
        var file = fs.createWriteStream('nca_d_rsa.crl');
        response.pipe(file);
    }
    // Add timeout.
    request.setTimeout(12000, function () {
        request.abort();
    });
});

 // await request('http://crl.pki.gov.kz/nca_d_rsa.crl').pipe(fs.createWriteStream('nca_d_rsa.crl'));

const getAsync = Promises.promisify(cmd.get, { multiArgs: true, context: cmd })
 




*/

function checkFileExists(filepath) {
    return new Promise((resolve, reject) => {
        fs.access(filepath, fs.F_OK, error => {
            resolve(!error);
        });
    });
}

var download = function(url, dest, cb) {
    var file = fs.createWriteStream(dest);
    var request = http.get(url, function(response) {
        response.pipe(file);
        file.on('finish', function() {
            file.close(cb);
        });
    });
}

function readLines({ input }) {
    const output = new stream.PassThrough({ objectMode: true });
    const rl = readline.createInterface({ input });
    rl.on("line", line => {
        output.write(line);
    });
    rl.on("close", () => {
        output.push(null);
    });
    return output;
}




async function CrlDownload(url, dest) {
    return new Promise((resolve, reject) => {
        try {
            let file = fs.createWriteStream(dest);
            let responseSent = false;
            http.get(url, response => {
                response.pipe(file);
                file.on('finish', () => {
                    file.close(() => {
                        if (responseSent) return;
                        responseSent = true;
                        resolve(true);
                    });
                });
            }).on('error', err => {
                if (responseSent) return;
                responseSent = true;
                reject(err);
            });
        } catch (err) {
            console.log('Error occurred CrlDownload', err);
            reject(err);
        }
    });
}

async function extractCrl(dest, command) {
    return new Promise((resolve, reject) => {
        try {
            let cmd = require('node-cmd');
            let Promises = require('bluebird');
            let local_fs = require('fs');
            local_fs.access(dest, fs.F_OK, (err) => {
                if (err) {
                    console.error('extractCrl err ' + dest + ' error reading ' + err)
                    reject(err);
                } else {
                    // console.log('extract begin ' + dest)
                }
            })
            let getAsync = Promises.promisify(cmd.get, { multiArgs: true, context: cmd })
            getAsync(command).then(data => {
                Cg.cnf.showlog && console.log('cmd executed command =' + command, data)
                resolve(true);
            }).catch(err => {
                console.error('cmd err on extractCrl', err)
                return;
            })
        } catch (err) {
            console.log('Error occurred extractCrl', err);
            reject(err);
        }

    });
}

async function downloadRevokedList(FileNameNoExt, P_oracledb) {
    try {
        Cg.gov_crl_http_options.path = 'http://crl.pki.gov.kz/' + FileNameNoExt + '.crl';
        //   console.log('Cg.gov_crl_http_options.path='+Cg.gov_crl_http_options.path)
        //  console.log('gov_crl_http_options='+JSON.stringify(Cg.gov_crl_http_options))
        let Downloaded = await CrlDownload(Cg.gov_crl_http_options.path, FileNameNoExt + '.crl');
        if (Downloaded !== true) { throw new Error('downloadRevokedList error') }
        let Extracted = await extractCrl(FileNameNoExt + '.crl', `openssl crl -inform DER -text -noout -in "` + FileNameNoExt + `.crl" > ` + FileNameNoExt + `.txt`)
        if (Extracted !== true) { throw new Error('downloadRevokedList error2') }   
        return new Promise((resolve, reject) => {
            try {
                let SerialNumbers = {};
                var Rownum = 0;
                let Sernums = [];
                let local_fs = require('fs');
                local_fs.access(FileNameNoExt + ".txt", fs.F_OK, (err) => {
                    if (err) {
                        console.error(FileNameNoExt + ".txt не найден")
                        return
                    } else {
                        console.log(FileNameNoExt + ".txt распокавался успешно")
                        fs.readFileSync(FileNameNoExt + ".txt").toString().split("\n").forEach(function(line, index, arr) {
                            if (index === arr.length - 1 && line === "") { return; }
                            if ((line.includes('Serial Number:')) && (Rownum < 1500)) {
                                Rownum++;
                                //  Sernums[{ CERT_NUM: Rownum, SERIAL_NUMBER: line.substring(line.indexOf(':') + 1, line.length).trim() }]
                                Sernums.push({ CERT_NUM: Rownum, SERIAL_NUMBER: line.substring(line.indexOf(':') + 1, line.length).trim() });
                                //  console.log(line.substring(line.indexOf(':') + 1, line.length).trim() + ' ' + Rownum);
                            }
                        });
                        if (((Sernums).length !== 0) && (Sernums !== undefined)) {
                            let answer = dqueries.InsCrl(P_oracledb, Sernums);
                            resolve(answer);
                        } else {
                            throw new Error('downloadRevokedList crl array is empty ')
                           // return 'downloadRevokedList crl array is empty ';
                        }

                    }
                })
               // resolve();
            } catch (err) {
                console.error('Error occurred of parser downloadRevokedList', err);
                reject(err);
            }
        });
    } catch (err) {
        console.log('Error occurred downloadRevokedList', err);
        return;
    }

}

async function validateXml(xml, value_node_name, P_oracledb) {
    return new Promise(async function(resolve, reject) {
        try {
            /////////////////////////////////////////////
            let doc = new dom().parseFromString(xml)
            let LocalSelect = xpath.useNamespaces({ "ds": "http://www.w3.org/2000/09/xmldsig#" });
            //  fs.writeFileSync('test signature add.xml', signature);
            let sig = new SignedXml()
            //   sig.keyInfoProvider = new FileKeyInfo("public_key.pem")
            //  sig.keyInfoProvider = new FileKeyInfo(key)
            sig.canonicalizationAlgorithm = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
            let X509Certificate = '-----BEGIN CERTIFICATE-----' + '\n' + LocalSelect('//ds:X509Certificate/text()', doc)[0].nodeValue + '\n' + '-----END CERTIFICATE-----';
            sig.keyInfoProvider = new ValidateKeyInfo(X509Certificate, 'ds')
            let signature = select(doc, `/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']`)[0]
            sig.loadSignature(signature.toString())
            let res = sig.checkSignature(xml)
            const issuer = Certificate.fromPEM(X509Certificate)
            // fs.writeFileSync('read_cert.json', JSON.parse(JSON.stringify(issuer.serialNumber)).toUpperCase());
            let sernum = JSON.parse(JSON.stringify(issuer.serialNumber)).toUpperCase();
            var FoundCerts = 1;
            let signedValue = LocalSelect('//' + value_node_name + '/text()', doc)[0].nodeValue;
            FoundCerts = await dqueries.CheckSerialNumber(P_oracledb, sernum).then(function whenOk(response) {
                    return response
                })
                .catch(function notOk(err) {
                    console.error(err)

                });

            console.log('FoundCerts = out ' + FoundCerts);
            if ((FoundCerts !== 0) || (FoundCerts == undefined)) {
                console.error('validateXml Сертификат не прошел валидацию ' + FoundCerts)
                //  reject('Сертификат не прошел валидацию ');
                return;
            }
            if (!res) {
                console.error(sig.validationErrors)
                return
                //  reject(sig.validationErrors);
            } else {
                console.log("xml validated succesfully . Resolved SignedValue = " + signedValue)
                resolve(signedValue);
            }
        } catch (err) {
            console.log('Error occurred validateXml', err);
            reject(err);
        } finally {

        }
    });
}



function ExampleTestSign(){
    return new Promise(async function (resolve, reject) {
        try {
            let FileNameNoExt = "nca_d_rsa";
            let xml = await xml_sign.downloadRevokedList(FileNameNoExt , oracledb);
            console.log("xml " + JSON.stringify(xml))

            let testvar = fs.readFileSync("delphi-signed-revoked.xml").toString();
            let value = await xml_sign.validateXml(testvar, "test_root" , oracledb);
            if (value == false) {
                console.log("signature not valid")
                return
            } else {
                console.log("signature is valid. value= " + value)
            }
            console.log('resul = ' + JSON.stringify(res))
            await db_queries.CheckSerialNumber(oracledb, '53C460EDD962AB7EB0D3A1D487D623565F231BD1')
            db_queries.syncdb(oracledb, '53C460EDD962AB7EB0D3A1D487D623565F231BD1' , Cg.db_options);
            resolve();
        } catch (err) {
            console.log('GetFreeCards an error occurred', err);
            reject(err);
        }
    });
}


//var publickey = fs.readFileSync("public_key.pem");


if (process.env.NODE_ENV == 'test') {
    //----------------------------------------------------------------
    //Начало
    let keyFile = fs.readFileSync("RSA.p12", 'binary');
    let p12Asn1 = forge.asn1.fromDer(keyFile);
    // pkcs12 с паролем
    let p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, 'Qwerty12');
    let bags = p12.getBags({ bagType: forge.pki.oids.certBag });
    // Сертификат
    let certBag = bags[forge.pki.oids.certBag][0];
    let cert = certBag.cert;
    //console.log(forge.pki.certificateToPem(cert));
    //-----BEGIN CERTIFICATE-----

    // Приватный ключ
    let keyBags = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag });
    let keyBag = keyBags[forge.pki.oids.pkcs8ShroudedKeyBag][0];
    let privateKey = keyBag.key;
    //console.log(forge.pki.privateKeyToPem(privateKey));
    //-----BEGIN RSA PRIVATE KEY-----


    // Публичный ключ
    let publicKey = forge.pki.setRsaPublicKey(privateKey.n, privateKey.e);
    //console.log(forge.pki.publicKeyToPem(publicKey));
    //-----BEGIN PUBLIC KEY-----

    // Проверка XMLDSIG 

    let xml =
        `<?xml version='1.0'?><library Id="123"><test_root>123</test_root></library>`;

    signXml(xml,
       // "//*[local-name(.)='test_root']",
       "/library",
        forge.pki.privateKeyToPem(privateKey),
        "result.xml")
    let signedXml = fs.readFileSync("self-signed.xml").toString();
    let value = validateXml(signedXml, "test_root");
    if (value == false) {
        console.log("signature not valid")
    } else {
       console.log("signature is valid. value= " + value) 
    } 
}



module.exports.validateXml = validateXml;
module.exports.downloadRevokedList = downloadRevokedList;