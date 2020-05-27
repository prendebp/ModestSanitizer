using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.ComponentModel.DataAnnotations;

namespace ModestSanitizer
{
    //   REASONABLY SECURE GENERAL PURPOSE LIBRARY TO SANITIZE INPUT THAT DOES NOT REQUIRE OUTPUT ENCODING.
    //   For output encoding see Anti-XSS
    //   For LDAP encoding see Anti-XSS

    //DATE FORMATTING:    ISO 8601 (yyyy-MM-dd'T'HH:mm:ssZ

    //   * USE ASYNC AND AWAIT* I guess. . . if you were doing I/O Bound or Network Bound stuff . . .

    //   REDUCE TO ONLY THREE OR FOUR METHODS IF POSSIBLE ?!?!?!?

    //   If users input data and that data is output back to the screen in a web response, that could be a way for hackers to attack called Cross-Site Scripting(XSS). The Anti-XSS library helps you to handle this. The Anti-XSS library may also help prevent against LDAP injection.
    //   But, what if you aren't displaying output back to the screen in a response?  What if you just pass data to a web service?  What if you just have a console app that takes arguments? What if you just pass data to an NServiceBus endpoint? Or just read a value to or from a plain text file or XML or JSON?
    //   In other words, I would like a library for developers to use to allow and encourage basic sanitization of any externally input data coming into any C# .NET app of any kind . . . 
    //   The risks here are lower but it's still likely a good practice . . . to do things like check values against a valid whitelist where possible or clean against basic SQL Injection attacks or throw (and log) exceptions if a hacker tries to pass in bad arguments to an app (exploring) and so catch them.
    //   This isn't meant to be perfect but to be a reasonably secure, modest sanitizer to encourage good and regular discipline by developers?
    //   I am envisioning something like the following features?
    //   0. TruncateToValidLength (e.g. max length of a string or max value of a number)
    //   Why? To protect against buffer overflow attacks, e.g. if using unsafe keyword: https://stackoverflow.com/questions/9343665/are-buffer-overflow-exploits-possible-in-c
    //   1. Validate datatype REMOVED - NOT AN ISSUE
    //   2. NormalizeUnicode
    //   OR
    //   3. LimitToASCIIOnly
    //   Why? To assist with safe whitelisting
    //   4. RegexInputValidation (optional) - e.g. validate URL syntax, phone number, etc.
    //      bool match = Regex.IsMatch(input, Regex.Escape(regex)); // Compliant  - avoid regular expression denial of service https://rules.sonarsource.com/csharp/type/Vulnerability/RSPEC-2631
    //      return Content("Valid? " + match);
    //      Allow only alphanumeric characters  if (value == null || !Regex.IsMatch(value, "^[a-zA-Z0-9]+$"))
    //   Why? To assist with safe whitelisting
    //   OR
    //   5. Check whitelist of valid values ASCII or Unicode (overload)  
    //   Why? To assist with safe whitelisting
    //   6. Interrogate if hexadecimal? %%, %p,%d,%c,%u,%x,%s,%n,\x
    //   Why? To protect against format string attacks with unsafe keyword: https://owasp.org/www-community/attacks/Format_string_attack
    //   7. Basic prevention of SQLInjection such as replacing ;,',--,* ... */,<,>,%,Or,xp_,sp_,exec_, or other SQL keywords?
    //   Why? To prevent against SQL Injection attacks if NOT parameterizing queries or using an ORM, or if explicitly using dynamic SQL
    //   8. Filename cleanse??? 
    //   Why? Prevent tricks with chars that simulate a dot (a period), etc.
    //   9. Throw exception on blacklist values (optional and un-advised, whitelist is better)
    //   10. Prevent OS Command injections, prevent calls to MSBuild.exe and RegAsm.exe, WriteAllText, reflection.Emit, Process.Start(), foldername && ipconfig, or /sbin/shutdown by blacklisting these string values
    //   11. Set CurrentCulture before performing String.Compare?  SOURCE: https://docs.microsoft.com/en-us/previous-versions/dotnet/netframework-1.1/5bz7d2f8(v=vs.71)?redirectedfrom=MSDN
    //Also, french(?) system locale. So converting your variable to string inserts a comma for the decimal separator. Your SQL Server wants a dot as a decimal separator if you use a SQL Statement.so your 3469,2 gets a 34692.
    //   12. Array of allowed values for small sets of string parameters (e.g. days of week).
    //   13. Parameter fuzzing exceptions - to tie to system alerts
    public class Sanitizer
    {
        public enum SaniTypes{ 
            None = 0,
            MinMax = 1,
            Truncate = 2,
            NormalizeOrLimit = 3,
            Whitelist = 4,
            SQLInjection = 5,
            FileNameCleanse = 6,
            Blacklist = 7
        }

        public enum SaniApproach
        {
            None = 0,
            TrackExceptionsInList = 1,
            ThrowExceptions = 2
        }

        public enum BlacklistType
        {
            None = 0,
            All = 1,
            OSCommandInjection = 2,
            FormatStringAttacks = 3
        }

        /// <summary>
        /// Sanitizer Approach to Exceptions
        /// </summary>
        public SaniApproach SanitizerApproach { get; set; }
        public MinMax MinMax {get;set;}

        public Dictionary<Guid, KeyValuePair<SaniTypes, string>> SaniExceptions { get; set; }

        public Sanitizer(SaniApproach sanitizerApproach) {
            SanitizerApproach = sanitizerApproach;
            if (sanitizerApproach == SaniApproach.TrackExceptionsInList)
            {
                SaniExceptions = new Dictionary<Guid, KeyValuePair<SaniTypes, string>>();
            }
            
            MinMax = new MinMax(SanitizerApproach, SaniExceptions);
        }

        //List<string> with list of sanitization errors mitigated

        /// <summary>
        /// TruncateToValidLength -  max length of a string
        /// </summary>
        /// <param name="strToClean"></param>
        /// <returns></returns>   
        public static string TruncateToValidLength(string strToClean, int strMaxLength)
        {
            string tmpResult = String.Empty;

            try
            {
                if (string.IsNullOrWhiteSpace(strToClean))
                {
                    tmpResult = strToClean;
                }
                else
                {
                    if (strToClean.Length >= strMaxLength)
                    {
                        tmpResult = strToClean.Substring(0, strMaxLength);
                    }
                    else
                    {
                        tmpResult = strToClean;
                    }
                }
            }
            catch (Exception ex)
            {
                throw new SanitizerException("Error truncating to valid length: " + (strToClean ?? String.Empty), ex);
            }
            return tmpResult;
        }

        //SOURCE: https://github.com/microsoft/referencesource/blob/master/System.ComponentModel.DataAnnotations/DataAnnotations/Validator.cs
        private static bool ValidateDataType(Type destinationType, object value)
        {
            if (destinationType == null)
            {
                throw new ArgumentNullException("destinationType");
            }

            if (value == null)
            {
                // Null can be assigned only to reference types or Nullable or Nullable<>
                return !destinationType.IsValueType ||
                        (destinationType.IsGenericType && destinationType.GetGenericTypeDefinition() == typeof(Nullable<>));
            }

            // Not null -- be sure it can be cast to the right type
            return destinationType.IsAssignableFrom(value.GetType());
        }

        /// <summary>
        /// 1. Normalize Unicode for if you are planning to compare against a Unicode Whitelist (so you know which Normalization Form to use.)
        /// </summary>
        /// <param name="strToClean"></param>
        /// <returns></returns>   
        public static string NormalizeUnicode(string strToClean)
        {
            string tmpResult = String.Empty;

            try
            {
                //SOURCE: https://stackoverflow.com/questions/15683717/unicode-to-ascii-conversion-mapping

                if (string.IsNullOrWhiteSpace(strToClean))
                {
                    tmpResult = strToClean;
                }
                else
                {
                    tmpResult = strToClean.Normalize(NormalizationForm.FormKC);

                    //This will retain diacritic characters after normalization.
                    tmpResult = new string(tmpResult.Where(c =>
                    {
                        UnicodeCategory category = CharUnicodeInfo.GetUnicodeCategory(c);
                        return category != UnicodeCategory.NonSpacingMark;
                    }).ToArray());
                }

            }
            catch (Exception ex)
            {
                throw new SanitizerException("Error normalizing unicode: " + (strToClean??String.Empty), ex);
            }

            return tmpResult;
        }

        /// <summary>
        /// 2. This will limit a Unicode string to just the limited subset of ASCII-compatible characters.
        /// </summary>
        /// <param name="strToClean"></param>
        /// <returns></returns>
        public static string LimitToASCIIOnly(string strToClean)
        {
            string tmpResult = String.Empty;
            bool removeAccents = true;

            try
            {

                //TODO: How to handle exceptions such as Pi, Euro, cent, etc.?


                if (string.IsNullOrWhiteSpace(strToClean))
                {
                    tmpResult = strToClean;
                }
                else
                {
                    tmpResult = strToClean.Normalize(NormalizationForm.FormKC);
                    
                    //SOURCES:
                    //https://stackoverflow.com/questions/1008802/converting-symbols-accent-letters-to-english-alphabet
                    //http://www.codecodex.com/wiki/Unaccent_letters
                    //http://www.unicode.org/Public/security/latest/confusables.txt
                    //https://stackoverflow.com/questions/4846365/find-characters-that-are-similar-glyphically-in-unicode
                    
                    if (removeAccents)
                    {
                        string PLAIN_ASCII =
                            "AaEeIiOoUu"    // grave ` (U+0060)
                          + "AaEeIiOoUuYy"  // acute ´ (U+00B4)
                          + "AaEeIiOoUuYy"  // circumflex ^ (U+005E)
                          + "AaOoNn"        // tilde ~ (U+007E) [Most frequent in Spanish such as "español".]
                          + "AaEeIiOoUuYy"  // diaeresis or umlaut ̈	 (U+0308)
                          + "AaUu"          // ring ̊  (U+030A) [Most frequent Danish or Swedish Å, but also potentially Ů in Czech.]
                          + "Cc"            // cedilla ̧  (U+00B8) [Most frequent character with cedilla is "ç" such as in "façade".]
                          + "OoUu";         // double acute ̋   (U+030B) [Most frequent in Hungarian for Ő and Ű.]

                        //For example, handles: Ù, Ú, Û, ñ, Ü, Ů, ç, Ű
                       
                        //TODO: Add support for the following: Ū, Ŭ

                        //Does NOT currently support the following diacritical chars: Ư, Ǔ, Ǖ, Ǘ, Ǚ, Ǜ, Ủ, Ứ, Ừ, Ử, Ữ, Ự";
                        
                        string UNICODE =
                          "\u00C0\u00E0\u00C8\u00E8\u00CC\u00EC\u00D2\u00F2\u00D9\u00F9"
                         + "\u00C1\u00E1\u00C9\u00E9\u00CD\u00ED\u00D3\u00F3\u00DA\u00FA\u00DD\u00FD"
                         + "\u00C2\u00E2\u00CA\u00EA\u00CE\u00EE\u00D4\u00F4\u00DB\u00FB\u0176\u0177"
                         + "\u00C3\u00E3\u00D5\u00F5\u00D1\u00F1"
                         + "\u00C4\u00E4\u00CB\u00EB\u00CF\u00EF\u00D6\u00F6\u00DC\u00FC\u0178\u00FF"
                         + "\u00C5\u00E5\u016E\u016F"
                         + "\u00C7\u00E7"
                         + "\u0150\u0151\u0170\u0171"
                         ;

                        // remove accentuated from a string and replace with ascii equivalent
                        StringBuilder sb = new StringBuilder();

                        int n = tmpResult.Length;
                        for (int i = 0; i < n; i++)
                        {
                            char c = tmpResult.ToCharArray()[i];
                            int pos = UNICODE.IndexOf(c);
                            if (pos > -1)
                            {
                                sb.Append(PLAIN_ASCII.ToCharArray()[pos]);
                            }
                            else
                            {
                                sb.Append(c);
                            }
                        }
                        tmpResult = sb.ToString();

                        //THIS WILL LIMIT TO JUST ASCII CHARACTERS. THIS WILL REMOVE ANY DIACRITIC CHARACTERS!!
                        tmpResult = new string(tmpResult.ToCharArray().Where(c => (int)c <= 127).ToArray());                       
                    }
                }

            }
            catch (Exception ex)
            {
                throw new SanitizerException("Error limiting unicode to ASCII: " + (strToClean ?? String.Empty), ex);
            }
            return tmpResult;
        }

               
        //https://www.codementor.io/@satyaarya/prevent-sql-injection-attacks-in-net-ocfxkhnyf
        //how to detect and/or prevent hexadecimal/binary/decimal? Octal?
               
        //In the long run, it's probably better to normalize all strings before storing them into a database. 
        //If the same text can be represented with different codepoint sequences, it will also cause troubles in database queries. 
        //And most database are unable to normalize strings. &#x30A;  second way to represent å is used.

        //https://stackoverflow.com/questions/54701176/unicode-normalization-form-c-in-asp-net-core-razor-view
        //https://docs.microsoft.com/en-us/dotnet/api/system.string.normalize?view=netframework-4.8

        //[Route("~/file/{id}")]
        //public async Task<IActionResult> File(int id)
        //{
        //FileViewModel m = await LoadFileAsync(id).ConfigureAwait(false);
        //m.Title = m.Title.Normalize(NormalizationForm.FormC);
        //return View(m);
        //}

        //Class to Prevent bad characters and bad strings
        //public static class BadChars
        //{
        //    public static char[] badChars = { ';', ',', '"', '%' };
        //    public static string[] badCommands = { "--", "xp_cmdshell", "Drop", "Update" };
        //}
        
        ////Defines the set of characters that will be checked.
        ////You can add to this list, or remove items from this list, as appropriate for your site
        //public static string[] blackList = {"--",";--",";","/*","*/","@@","@",
        //                                           "char","nchar","varchar","nvarchar",
        //                                           "alter","begin","cast","create","cursor","declare","delete","drop","end","exec","execute",
        //                                           "fetch","insert","kill","open",
        //                                           "select", "sys","sysobjects","syscolumns",
        //                                           "table","update"};

        //public void Dispose()
        //{
        //    //no-op 
        //}

        ////Tells ASP.NET that there is code to run during BeginRequest
        //public void Init(HttpApplication app)
        //{
        //    app.BeginRequest += new EventHandler(app_BeginRequest);
        //}

        ////For each incoming request, check the query-string, form and cookie values for suspicious values.
        //void app_BeginRequest(object sender, EventArgs e)
        //{
        //    HttpRequest Request = (sender as HttpApplication).Context.Request;

        //    foreach (string key in Request.QueryString)
        //        CheckInput(Request.QueryString[key]);
        //    foreach (string key in Request.Form)
        //        CheckInput(Request.Form[key]);
        //    foreach (string key in Request.Cookies)
        //        CheckInput(Request.Cookies[key].Value);
        //}

        ////The utility method that performs the blacklist comparisons
        ////You can change the error handling, and error redirect location to whatever makes sense for your site.
        //private void CheckInput(string parameter)
        //{
        //    for (int i = 0; i < blackList.Length; i++)
        //    {
        //        if ((parameter.IndexOf(blackList[i], StringComparison.OrdinalIgnoreCase) >= 0))
        //        {
        //            //
        //            //Handle the discovery of suspicious Sql characters here
        //            //
        //            HttpContext.Current.Response.Redirect("~/Error.aspx");  //generic error page on your site
        //        }
        //    }
        //}

        //    }
        //SOURCE: https://forums.asp.net/t/1254125.aspx

    }
}
