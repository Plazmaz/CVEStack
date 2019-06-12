## CVEStack
![Example message](https://i.imgur.com/jOFb609.png)   
_An example message_  

Scans feeds for various elements within the stack, then posts to various sources. Currently syslog, RSS, and slack are supported.. Supports a pip-style format. For instance, this file:
```
linux
wordpress
````
Will post to output(s) for any new (or recently updated) CVEs matching `linux` or `wordpress`.
You can use `__` to determine left or right padding on a per-pattern basis. For instance, `__py` would match ' testpy', but not 'testpy '. Similarly, `py__` would match 'testpy ', but not ' testpy'.
You can also specify required combinations of keywords. For instance,
`linux & kernel`
will require that an entry contains both `linux` and `kernel`.

You can also set required keywords to be negative. For instance, this line will match entries for 'sql', but not if they also contain 'server':
`sql & -server`  

If you prefer blacklisting to whitelisting, you can enable that in the config by switching `dependencies_are_ignored` to true. This
will ignore all feed entries matching an item in your dependencies file.

The example config pulls from nvd and seclists. It posts to a syslog at /dev/log by default.
