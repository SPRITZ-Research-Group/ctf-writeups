[writeup by @TheNodi]

**CTF:** HXP CTF 2017

**Team:** spritzers (from [SPRITZ Research Group](http://spritz.math.unipd.it/))

**Task:** misc / Irrgarten

The only hint we are given is a dig command querying a DNS Server: 

```
dig -t txt -p53535 @35.198.105.104 950ae439-d534-4b0c-8722-9ddcb97a50f6.maze.ctf.link
```

We executed it and the answer was a TXT record saying `Try down.<domain>`.

We queried `down.950ae439-d534-4b0c-8722-9ddcb97a50f6.maze.ctf.link` and received a CNAME record pointing to `569b8ba8-ac9a-4d60-a816-10d13b3d7021.maze.ctf.link`.

After playing around with the DNS Server, we understood that every URL was a position in a maze and we could move by prepending `down/up/right/left` to the address.

At this point it was as easy as to code a [Wall Follower](https://en.wikipedia.org/wiki/Maze_solving_algorithm#Wall_follower) algorithm and let it run for a few minutes. When we faced a "dead end" we checked the TXT record associated with that address, to check if it contained the flag.

At the end we found the flag to be: `hxp{w3-h0p3-y0u-3nj0y3d-dd051n6-y0ur-dn5-1rr364r73n}`.

### Automated Script

```js
const dns = require('dns');

dns.setServers([
    '35.198.105.104:53535'
]);

/**
 * Get information for given position
 * 
 * @param {string} position 
 */
function info(position) {
    return new Promise((resolve, reject) => {

        dns.resolveTxt(`${position}.maze.ctf.link`, (err, records) => {

            if (err || records.length === 0) {
                resolve(false);
            } else {
                resolve(records);
            }

        });

    });
}

/**
 * Move from given position into a direction
 * 
 * @param {string} position 
 * @param {string} direction 
 */
function moveTo(position, direction) {
    return new Promise((resolve, reject) => {

        dns.resolveCname(`${direction}.${position}.maze.ctf.link`, (err, records) => {

            if (err || records.length === 0) {
                resolve(false);
            } else {
                resolve(records[0].replace('.maze.ctf.link', ''));
            }

        });

    });
}

const followerDirections = {
    down: ['left', 'down', 'right'],
    up: ['right', 'up', 'left'],
    right: ['down', 'right', 'up'],
    left: ['up', 'left', 'down'],
};

const visited = [];

/**
 * Wall Follower Maze solver
 * 
 * @param {string} start 
 * @param {string} from 
 */
async function solve(start, from) {
    visited.push(start);
    let moved = false;

    for (let i = 0; i < 3; i++) {
        const direction = followerDirections[from][i];

        const next = await moveTo(start, direction);

        if (next !== false) {

            if (visited.indexOf(next) > -1) {
                console.log(`\x1b[37mVisited: ${next}\x1b[0m`);
                return;
            }

            moved = true;

            await solve(next, direction);
        }
    }

    if (!moved) {
        console.log(`\x1b[90mDead end: ${start}\x1b[0m`);

        const txt = await info(start);

        if (txt !== false) {
            console.log(`\x1b[41mInfo: ${txt}\x1b[0m`);
        }
    }
}

solve('950ae439-d534-4b0c-8722-9ddcb97a50f6', 'down');
```
