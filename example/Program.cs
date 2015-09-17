// Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.IO;
using LastPass;

namespace Example
{
    class Program
    {
        static void Main(string[] args)
        {
            // Read LastPass credentials from a file
            // The file should contain 2 lines: username and password.
            // See credentials.txt.example for an example.
            var credentials = File.ReadAllLines("../../credentials.txt");
            var username = credentials[0];
            var password = credentials[1];

            // Fetch and create the vault from LastPass
            Vault vault = null;
            try
            {
                // Frist try basic authentication
                vault = Vault.Create(username, password);
            }
            catch (LoginException e)
            {
                switch (e.Reason)
                {
                case LoginException.FailureReason.LastPassIncorrectGoogleAuthenticatorCode:
                    {
                        // Request Google Authenticator code
                        Console.Write("Enter Google Authenticator code: ");
                        var code = Console.ReadLine();

                        // Now try with GAuth code
                        vault = Vault.Create(username, password, code);

                        break;
                    }
                case LoginException.FailureReason.LastPassIncorrectYubikeyPassword:
                    {
                        // Request Yubikey password
                        Console.Write("Enter Yubikey password: ");
                        var yubikeyPassword = Console.ReadLine();

                        // Now try with Yubikey password
                        vault = Vault.Create(username, password, yubikeyPassword);

                        break;
                    }
                default:
                    {
                        throw;
                    }
                }
            }

            // Dump all the accounts
            for (var i = 0; i < vault.Entries.Length; ++i)
            {
                var entry = vault.Entries[i];

                var account = entry as Account;
                if (account != null)
                {
                    // Need explicit converstion to string.
                    // String.Format doesn't do that for EncryptedString.
                    Console.WriteLine("{0}: {1} {2} {3} {4} {5} {6}",
                                      i + 1,
                                      account.Id,
                                      (string)account.Name,
                                      (string)account.Username,
                                      (string)account.Password,
                                      account.Url,
                                      (string)account.Group);
                }

                var genericNote = entry as GenericNote;
                if (genericNote != null)
                {
                    Console.WriteLine("{0}: {1} {2} {3}",
                                      i + 1,
                                      genericNote.Id,
                                      (string)genericNote.Name,
                                      genericNote.Contents);
                }
            }
        }
    }
}
