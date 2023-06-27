using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net.Http;
using System.Security.Cryptography;
using RestSharp;

namespace HaveIBeenPwnedAPI
{

    /// <summary>
    /// V3 API for https://haveibeenpwned.com/
    /// </summary>
    public class HaveIBeenPwnedApiV3
    {
        
        /// <summary>
        /// Determine if the password has been found in a hack
        /// </summary>
        /// <param name="ApiKey">API Key from https://haveibeenpwned.com/API/Key</param>
        /// <param name="UserAgent">String to indicate what application is using the API</param>
        /// <param name="PlainPassword">The password to be checked</param>
        /// <returns>The number of data breaches the password has been found in</returns>
        public static  Int64 PasswordCheck(string ApiKey, string UserAgent, string PlainPassword)
        {
            // The API only takes the first 5 of the SHA1 hashed password and only returns
            // the last part of the SHA1 hashed password
            string sha1Password = Hash(PlainPassword);
            string sha1PasswordRange = sha1Password.Substring(0, 5);
            string sha1PasswordSuffix = sha1Password.Substring(5);
            string pwnedURI = $"https://api.pwnedpasswords.com/range/{sha1PasswordRange}";
           
            RestResponse response = CallPwnedRestApi(ApiKey, UserAgent, pwnedURI);

            //	Not found — the account could not be found and has therefore not been pwned
            if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                return 0;
            }

            // Handle errors
            if (response.StatusCode != System.Net.HttpStatusCode.OK)
            { HandlePwnedApiErrors(ApiKey, response); }


            long retVal;
            // Check to see if the requested password is in the returned list
            if (response.Content.IndexOf(sha1PasswordSuffix) == -1)
            { return 0; }
            else
            {
                int hashLocation = response.Content.IndexOf(sha1PasswordSuffix);
                int eolLocation = response.Content.IndexOf('\r', hashLocation);
                int colonLocation = response.Content.IndexOf(':', hashLocation);
                string count = response.Content.Substring(colonLocation + 1, eolLocation - colonLocation);
                Int64.TryParse(count, out retVal);
            }
            return retVal;

        }

        private static void HandlePwnedApiErrors(string ApiKey, RestResponse response)
        {
            if (response.StatusCode != System.Net.HttpStatusCode.OK)
            {
                string errorMessage;
                switch (response.StatusCode)
                {
                    case System.Net.HttpStatusCode.Unauthorized:
                        errorMessage = $"API {ApiKey} is not authorized"; break;
                    case System.Net.HttpStatusCode.Forbidden:
                        errorMessage = $"User Agent Not supplied"; break;
                    default: errorMessage = $"Call returned {response.StatusCode} ({response.StatusDescription})"; break;
                }
                throw new HttpRequestException(errorMessage);
            }
        }

        private static RestResponse CallPwnedRestApi(string ApiKey, string UserAgent, string pwnedURI)
        {
            var client = new RestClient(pwnedURI);
            var request = new RestRequest
            {
                Method = Method.Get
            };
            request.AddHeader("hibp-api-key", ApiKey);
            if (string.IsNullOrEmpty(UserAgent))
            {
                throw new HttpRequestException($"User Agent Not supplied");
            }
            request.AddHeader("user-agent", UserAgent);
            var response = client.Get(request);
            return response;
        }

        /// <summary>
        /// Determine all the breaches the email address has been involved in.
        /// </summary>
        /// <param name="ApiKey">API Key from https://haveibeenpwned.com/API/Key</param>
        /// <param name="UserAgent">String to indicate what application is using the API</param>
        /// <param name="EmailAddress">Email address to be searched for</param>
        /// <returns>Array of breach names that the email address has been involved in. If the number of breaches is 0 (zero) than the email address has not been involved in a breach</returns>
        public static List<HaveIBeenPwnedBreach> GetBreachesForEmailAddress(string ApiKey, string UserAgent, string EmailAddress)
        {
            string pwnedURI = $"https://haveibeenpwned.com/api/v3/breachedaccount/{EmailAddress}";
            RestResponse response = CallPwnedRestApi(ApiKey, UserAgent, pwnedURI);

            //	Not found — the account could not be found and has therefore not been pwned
            if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                return null;
            }
            // Handle errors
            if (response.StatusCode != System.Net.HttpStatusCode.OK)
            { HandlePwnedApiErrors(ApiKey, response); }
            return Newtonsoft.Json.JsonConvert.DeserializeObject<List<HaveIBeenPwnedBreach>>(response.Content);
        }

        /// <summary>
        /// Check for pastes that have been found that include this email address
        /// </summary>
        /// <param name="ApiKey">API Key from https://haveibeenpwned.com/API/Key</param>
        /// <param name="UserAgent">String to indicate what application is using the API</param>
        /// <param name="EmailAddress">Email address to be searched for</param>
        /// <returns>List of pastes with details</returns>
        public static HaveIBeenPwnedPastes CheckPastes(string ApiKey, string UserAgent, string emailAddress)
        {
            string pwnedURI = $"https://haveibeenpwned.com/api/v3/pasteaccount/{emailAddress}";
            RestResponse response = CallPwnedRestApi(ApiKey, UserAgent, pwnedURI);
            //	Not found — the account could not be found and has therefore not been pwned
            if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                return new HaveIBeenPwnedPastes();
            }

            // Handle errors
            if (response.StatusCode != System.Net.HttpStatusCode.OK)
            {
                HandlePwnedApiErrors(ApiKey, response);
            }
            return Newtonsoft.Json.JsonConvert.DeserializeObject<HaveIBeenPwnedPastes>(response.Content);

        }
        
        
        static string Hash(string input)
        {
            using (SHA1Managed sha1 = new SHA1Managed())
            {
                var hash = sha1.ComputeHash(Encoding.UTF8.GetBytes(input));
                var sb = new StringBuilder(hash.Length * 2);

                foreach (byte b in hash)
                {
                    sb.Append(b.ToString("X2"));
                }

                return sb.ToString();
            }
        }
    }

    public class HaveIBeenPwnedPastes : List<HaveIBeenPwnedPaste> { }
    
    public class HaveIBeenPwnedPaste
    {
        /// <summary>
        /// The paste service the record was retrieved from. Current values are: Pastebin, Pastie, Slexy, Ghostbin, QuickLeak, JustPaste, AdHocUrl, PermanentOptOut, OptOut
        /// </summary>
        public string Source { get; set; }
        /// <summary>
        /// The ID of the paste as it was given at the source service. Combined with the "Source" attribute, this can be used to resolve the URL of the paste.
        /// </summary>
        public string Id { get; set; }
        /// <summary>
        /// The title of the paste as observed on the source site. This may be null and if so will be omitted from the response.
        /// </summary>
        public string Title { get; set; }
        /// <summary>
        /// The date and time (precision to the second) that the paste was posted. This is taken directly from the paste site when this information is available but may be null if no date is published.
        /// </summary>
        public DateTime? Date { get; set; }
        /// <summary>
        /// The number of emails that were found when processing the paste. Emails are extracted by using the regular expression \b[a-zA-Z0-9\.\-_\+]+@[a-zA-Z0-9\.\-_]+\.[a-zA-Z]+\b
        /// </summary>
        public int EmailCount { get; set; }
    }

    public class HaveIBeenPwnedBreach
    {
        /// <summary>
        /// A Pascal-cased name representing the breach which is unique across all other breaches. This value never changes and may be used to name dependent assets (such as images) but should not be shown directly to end users (see the "Title" attribute instead).
        /// </summary>
        public string Name { get; set; }
        /// <summary>
        /// A descriptive title for the breach suitable for displaying to end users. It's unique across all breaches but individual values may change in the future (i.e. if another breach occurs against an organisation already in the system). If a stable value is required to reference the breach, refer to the "Name" attribute instead.
        /// </summary>
        public string Title { get; set; }
        /// <summary>
        /// The domain of the primary website the breach occurred on. This may be used for identifying other assets external systems may have for the site.
        /// </summary>
        public string Domain { get; set; }
        /// <summary>
        /// The date (with no time) the breach originally occurred on in ISO 8601 format. This is not always accurate — frequently breaches are discovered and reported long after the original incident. Use this attribute as a guide only.
        /// </summary>
        public DateTime BreachDate { get; set; }
        /// <summary>
        /// The date and time (precision to the minute) the breach was added to the system in ISO 8601 format.
        /// </summary>
        public DateTime AddedDate { get; set; }
        /// <summary>
        /// The date and time (precision to the minute) the breach was modified in ISO 8601 format. This will only differ from the AddedDate attribute if other attributes represented here are changed or data in the breach itself is changed (i.e. additional data is identified and loaded). It is always either equal to or greater then the AddedDate attribute, never less than.
        /// </summary>
        public DateTime ModifiedDate { get; set; }
        /// <summary>
        /// The total number of accounts loaded into the system. This is usually less than the total number reported by the media due to duplication or other data integrity issues in the source data.
        /// </summary>
        public int PwnCount { get; set; }
        /// <summary>
        /// Contains an overview of the breach represented in HTML markup. The description may include markup such as emphasis and strong tags as well as hyperlinks.
        /// </summary>
        public string Description { get; set; }
        /// <summary>
        /// A URI that specifies where a logo for the breached service can be found. Logos are always in PNG format.
        /// </summary>
        public string LogoPath { get; set; }
        /// <summary>
        /// This attribute describes the nature of the data compromised in the breach and contains an alphabetically ordered string array of impacted data classes.
        /// </summary>
        public List<string> DataClasses { get; set; }
        /// <summary>
        /// Indicates that the breach is considered unverified. An unverified breach may not have been hacked from the indicated website. An unverified breach is still loaded into HIBP when there's sufficient confidence that a significant portion of the data is legitimate.
        /// </summary>
        public bool IsVerified { get; set; }
        /// <summary>
        /// Indicates that the breach is considered unverified. An unverified breach may not have been hacked from the indicated website. An unverified breach is still loaded into HIBP when there's sufficient confidence that a significant portion of the data is legitimate.
        /// </summary>
        public bool IsFabricated { get; set; }
        /// <summary>
        /// Indicates if the breach is considered sensitive. The public API will not return any accounts for a breach flagged as sensitive.
        /// </summary>
        public bool IsSensitive { get; set; }
        /// <summary>
        /// 	Indicates if the breach has been retired. This data has been permanently removed and will not be returned by the API.
        /// </summary>
        public bool IsRetired { get; set; }
        /// <summary>
        /// 	Indicates if the breach has been retired. This data has been permanently removed and will not be returned by the API.
        /// </summary>
        public bool IsSpamList { get; set; }
        /// <summary>
        /// Indicates if the breach is sourced from malware. This flag has no impact on any other attributes, it merely flags that the data was sourced from a malware campaign rather than a security compromise of an online service.
        /// </summary>
        public bool IsMalware { get; set; }
    }

       
    public class HaveIBeenPwnedBreachName
    {
        /// <summary>
        /// A Pascal-cased name representing the breach which is unique across all other breaches. This value never changes and may be used to name dependent assets (such as images) but should not be shown directly to end users.
        /// </summary>
        public string Name { get; set; }
    }


}
