var pherz = require('./nodepherz');
var { URL } = require('url');
var ip = require('ip');
var { exec } = require('child_process');
var { createHash } = require('crypto');
var { waterfall } = require('async');
var { readFileSync } = require('fs');

const SOURCE = readFileSync('./app.js');
const FLAG = readFileSync('/flag.txt');

function sandbox_directory(ip) {
  return 'sandbox/' + createHash('md5').update('pa_ssion').update(ip).digest('hex'); 
}

var app = new pherz();

app.hostname = 'web.chal.csaw.io'
app.port = 4333

app.selector('/', function(req, res, done) {
  res.listing([
    {
      type: 'T',
      data: 'Hey man, I heard you like writing clients, try writing a server!'
    },
    {
      type: 'T',
      data: SOURCE,
    },
    {
      type: 'L',
      selector: '/reset'
    },
    {
      type: 'L',
      selector: '/run_client',
      parameters: [
        {
          key: 'host',
          value: '0.0.0.0'
        },
        {
          key: 'port',
          value: '3002'
        },
      ],
    },
  ]);
  done();
});

app.selector('/reset', function(req, res, done){
  let sandbox = sandbox_directory(req.client.remoteAddress);
  exec(`rm -rf ${sandbox}`, (err) => {
    if (err) {
      res.listing([{
        type: 'E',
        data: stderr,
      }]);
    } else {
      res.listing([{
        type: 'T',
        data: 'Reset sandbox!',
      }]);
    }
    done();
  });
});

app.selector('/run_client', function(req, res, done) {
  let {host, port} = req.params;
  let _url = `gopherz2://${host}:${port}`;  //url injection ? 
  let url;
  try {
    url = new URL(_url);
  } catch (e) {
    res.listing([{
      type: 'E',
      data: 'Yeah that\'s not going to work',
    }]);
    return done();
  }
  host = url.hostname;
  port = url.port;                        //se l'url è corretto (possibile gopherz://asd:30:30/ )?

  let sandbox = sandbox_directory(req.client.remoteAddress);  
  if (host && port) {
    waterfall([
      (cb) => { //crea sandbox e ci butta dentro client.py. Il tutto in modo asincrono al primo
        exec(`mkdir ${sandbox} && chmod +rwx ${sandbox} && cp client.py ${sandbox}/ && chmod 777 ${sandbox}`, (err, stderr, stdout) => { if (err) cb(stderr); else cb(); });
      },
      (cb) => {
        exec(`cd ${sandbox} && python3 client.py ${host} ${port}`,  // esegue client.py (in teoria nessuna inienzione)
          (err, stdout, stderr) => {
            if(err) cb(stderr);
            else {
              res.listing([{
                type:'T',
                data: stdout,
              }]);
              done();
            }
        });
      }
    ], (err) => {
      if(err) {
        res.listing([{
          type: 'E',
          data: err
        }]);
        done();
      }
    })
  } else {
    res.listing([{
      type: 'E',
      data: 'host and port wrong'
    }]);
    done();
  }
});

exec('mkdir sandbox', (err, stderr, stdout) => {
  app.listen();
});