using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using CommandLine;

namespace HaveIBeenPwnedApiConsoleApp
{
    internal class Program
    {
        public class Options
        {
            [Option("apiKey", Required =true, HelpText = "ApiKey from https://haveibeenpwned.com/API/Key")]
            public string apiKey { get; set; }

            [Option("emailAddress", Required = false, HelpText = "Email Address for testing pastes, breaches")]
            public string emailAddress { get; set; }

            [Option("password", Required =false, HelpText ="Password to look up")]
            public string password { get; set; }

            [Option("breach", Required = false, HelpText = "Breach name to get more information on breaches")]
            public string breach { get; set; }

            [Option("passwordCheck", Required =false, HelpText ="Check a password to see if it is valid. Requires including password option")]
            public bool passwordCheck { get; set; }

            [Option("breachesCheck", Required = false, HelpText = "Check an email is in breaches. Requires including emailAddress option")]
            public bool breachesCheck { get; set; }

        }

        static void Main(string[] args)
        {
            string userAgent = "azure-architect.com-ConsoleApp";
            Parser.Default.ParseArguments<Options>(args)
                  .WithParsed<Options>(o =>
                  {
                      if (o.passwordCheck)
                      {
                          long numberOfBreachesFoundForPassword = HaveIBeenPwnedAPI.HaveIBeenPwnedApiV3.PasswordCheck(o.apiKey, userAgent, o.password);
                          if(numberOfBreachesFoundForPassword==0) { Console.WriteLine($"That password has not been found in any breaches"); }
                          else { Console.WriteLine($"That password has been found in {numberOfBreachesFoundForPassword} breaches\r\nRecommend not to use"); }

                      }
                      if(o.breachesCheck)
                      {
                          List<HaveIBeenPwnedAPI.HaveIBeenPwnedBreach> breaches = HaveIBeenPwnedAPI.HaveIBeenPwnedApiV3.GetBreachesForEmailAddress(o.apiKey, userAgent, o.emailAddress);
                          if(breaches == null) { Console.WriteLine("That email address has been involved in no breaches"); }
                          else { Console.WriteLine($"That email address has been involved in the following breaches"); 
                          foreach(var x in breaches)
                              {
                                  Console.WriteLine($"{x.Name}");
                              }
                          }
                      }
                  });
        }         
    }
}
