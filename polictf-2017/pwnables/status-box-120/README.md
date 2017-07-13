[write-up by mi0s]

**CTF:** PoliCTF 2017

**Team:** spritzers (from [SPRITZ Research Group](http://spritz.math.unipd.it/))

**Task:** Pwnables / Status Box

**Points:** 120

# Challenge

> This Box memorizes a statuses sequence composed by a current status and all the previous ones.
> It already contains a small sequence of statuses, but you can show only the current one.
> You can set a new status, modify the current one or delete it: in this way the box goes back to the previous one in the sequence.
> The box can keep track of maximum 200 statuses. It seems just to work fine, even though we didn't test it a lot...;

The hostname and the port of the box were given:

`nc statusbox.chall.polictf.it 31337`

# Analysis

Since we know nothing about the box, the first thing we do is connecting to it using netcat.

The following output is printed on the CLI:

> StatusBox started! This Box memorizes a statuses
> sequence composed by a current status and all the previous ones.
> It already contains a small sequence of statuses, but you can show
> only the current one.
> You can set a new status, modify the current one or delete it: in this way
> the box goes back to the previous one in the sequence.
> The box can keep track of maximum 200 statuses.
> It seems just to work fine, even though we didn't test it a lot...
> CURRENT STATUS:
> This is the status set as default current status, change it!
>
>
> Choose your action:
>
> 0 - Print the current status;
>
> 1 - Set a new current status;
>
> 2 - Delete the current status and go back to the previous one;
>
> 3 - Modify the current status.
>
> 4 - Exit (statuses will be lost.)

All the info we need is given in the header part:

* It already contains a small sequence of statuses, but you can only show the current one;

* You can set a new status, modify the current one or delete it: in this way the box goes back to the previous one in the sequence.

So, we can suppose that there is something before the first status. The problem is:

__how can we reach it?__

Also, we are restricted to only four meaningful actions: *print*, *set*, *delete* and *modify*.

In this scenario the restriction is good for us, we know exactly what we can do. We only have to find the correct sequence of actions.

# Fail to win

The straightforward approach is to delete all the statuses to reach the ones before the first. But when we try to delete the first one, the process loops in the same status without proceeding any further.

At this stage only two useful actions were left:

* set;

* modify.

Note that print does not modify the status.

Uhm...we start thinking about how to use them while re-reading the header:

> It seems just to work fine, even though we didn’t test it a lot…

Ok, probably one of them is buggy. We start checking the corner cases for an input string.

First, we try the modify action by replacing the current status with an empty string.

The box replies with:
>
> Your choice was: 3
> Insert the new status, it will modify the current one:
>
> You set the current state to empty, so it was deleted.
> Going back to the previous state.
>
> Choose your action:
>
> 0 - Print the current status;
>
> 1 - Set a new current status;
>
> 2 - Delete the current status and go back to the previous one;
>
> 3 - Modify the current status.
>
> 4 - Exit (statuses will be lost.)
>
> 0
>
> Your choice was: 0
>
> CURRENT STATUS:
>
> That's strange...
>
> Choose your action:
>
> 0 - Print the current status;
>
> 1 - Set a new current status;
>
> 2 - Delete the current status and go back to the previous one;
>
> 3 - Modify the current status.
>
> 4 - Exit (statuses will be lost.)
>
> 3
>
> Your choice was: 3
>
> Insert the new status, it will modify the current one:
>
> You set the current state to empty, so it was deleted.
>
> Going back to the previous state.
>
> Choose your action:
>
> 0 - Print the current status;
>
> 1 - Set a new current status;
>
> 2 - Delete the current status and go back to the previous one;
>
> 3 - Modify the current status.
>
> 4 - Exit (statuses will be lost.)
>
> 0
>
> Your choice was: 0
>
> CURRENT STATUS:
>
> Are you sure of what you're doing?
>
> ...

It works!

When we modify the current status with an empty string the process deletes the current status and give us access to the previous status of the sequence.
Unfortunately, the flag isn't at the -1 status. However, the process give us some hints that make us think that the flag could be hidden deeper in the sequence.
Ok, hoping to find the flag by manually iterating the sequence is a PITA... not an option!

So, we automate the process with a shell oneliner which iterates the sequence, generating a log of the actions and inspecting it for the flag:

```bash
cat <(for i in $(seq 0 99); do echo "0"; sleep 2s; echo "3"; sleep 2s; echo ""; done;) | nc statusbox.chall.polictf.it 31337 | tee status_box.log && cat status_box.log | grep -E "flag{|FLAG{"
```

Since we do not know how far we have to search, we cat a subshell which iterates over 100 statuses for the first try. The sleep command is a dirty trick used to wait between two actions so that the process will correctly recognize them. Then we tee stdout because we may want to check from time to time if the search is going well while generating the log file. Since the flag format was given in the polictf instruction section, we can easily grep it from the generated log file. The search will take about 100*4s = 400s.

The resulting flag is: `flag{g00d_0ld_m1ss1ng_ch3cks!}`.