LastPass C# API
===============

## No longer supported

This project is no longer supported. There's a fully supported and regularly 
updated C# library that implements access to a veriety of password managers, 
including LastPass. Please check out 
[Password Manager Access](https://github.com/detunized/password-manager-access).

---

**This is unofficial LastPass API.**

This is a port of [Ruby API](https://github.com/detunized/lastpass-ruby).

This library implements fetching and parsing of LastPass data.  The library is
still in the proof of concept stage and doesn't support all LastPass features
yet.  Only account information (logins, passwords, urls, etc.) is available so
far.

There is a low level API which is used to fetch the data from the LastPass
server and parse it. Normally this is not the one you would want to use. What
you want is the `Vault` class which hides all the complexity and exposes all
the accounts already parsed, decrypted and ready to use. See the example
program for detail.

A quick example of accessing your account information:

```csharp
using LastPass;

var vault = Vault.Create(username, password);
foreach (var i in vault.Accounts)
    Console.WriteLine("{0}: {1}, {2}", i.Name, i.Username, i.Password);
```

The blob received from LastPass could be safely stored locally (it's well
encrypted) and reused later on.


Contributing
------------

Contribution in any form and shape is very welcome.  Have comments,
suggestions, patches, pull requests?  All of the above are welcome.


License
-------

The library is released under [the MIT
license](http://www.opensource.org/licenses/mit-license.php).
