using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.ComponentModel.DataAnnotations;

namespace ModestSanitizer
{
    /// <summary>
    /// REASONABLY SECURE GENERAL PURPOSE LIBRARY TO SANITIZE INPUT THAT DOES NOT REQUIRE OUTPUT ENCODING.
    /// For output encoding see Anti-XSS.
    //  For LDAP encoding see Anti-XSS.
    /// </summary>
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
        public Truncate Truncate { get; set; }
        public NormalizeOrLimit NormalizeOrLimit { get; set; }
        public FileNameCleanse FileNameCleanse { get; set; }

        public Dictionary<Guid, KeyValuePair<SaniTypes, string>> SaniExceptions { get; set; }

        public Sanitizer(SaniApproach sanitizerApproach) {
            SanitizerApproach = sanitizerApproach;
            if (sanitizerApproach == SaniApproach.TrackExceptionsInList)
            {
                SaniExceptions = new Dictionary<Guid, KeyValuePair<SaniTypes, string>>();
            }

            Truncate = new Truncate(SanitizerApproach, SaniExceptions);
            MinMax = new MinMax(Truncate, SanitizerApproach, SaniExceptions);
            NormalizeOrLimit = new NormalizeOrLimit(Truncate, SanitizerApproach, SaniExceptions);
            FileNameCleanse = new FileNameCleanse(Truncate, NormalizeOrLimit, SanitizerApproach, SaniExceptions);
        }

        #region High-level List of Next Features to Add
        //   2. RegexInputValidation (optional) - e.g. validate URL syntax, phone number, etc.
        //See OWASP Regex examples here: https://owasp.org/www-community/OWASP_Validation_Regex_Repository
        //      Allow only alphanumeric characters  if (value == null || !Regex.IsMatch(value, "^[a-zA-Z0-9]+$"))
        //   Why? To assist with safe whitelisting
        //   OR
        //   5. Check whitelist of valid values ASCII or Unicode (overload)  
        //   Why? To assist with safe whitelisting
        //   6. Interrogate if hexadecimal? %%, %p,%d,%c,%u,%x,%s,%n,\x
        //   Why? To protect against format string attacks with unsafe keyword: https://owasp.org/www-community/attacks/Format_string_attack
        //   7. Basic prevention of SQLInjection such as replacing ;,',--,* ... */,<,>,%,Or,xp_,sp_,exec_, or other SQL keywords?
        //   Why? To prevent against SQL Injection attacks if NOT parameterizing queries or using an ORM, or if explicitly using dynamic SQL
        //   8. Filename cleanse??? Path cleanse?
        //   Why? Prevent tricks with chars that simulate a dot (a period), etc.
        //   9. Throw exception on blacklist values (optional and un-advised, whitelist is better)
        //   10. Prevent OS Command injections, prevent calls to MSBuild.exe and RegAsm.exe, WriteAllText, reflection.Emit, Process.Start(), foldername && ipconfig, or /sbin/shutdown by blacklisting these string values
        //   11. Set CurrentCulture before performing String.Compare?  SOURCE: https://docs.microsoft.com/en-us/previous-versions/dotnet/netframework-1.1/5bz7d2f8(v=vs.71)?redirectedfrom=MSDN
        //Also, french(?) system locale. So converting your variable to string inserts a comma for the decimal separator. Your SQL Server wants a dot as a decimal separator if you use a SQL Statement.so your 3469,2 gets a 34692.
        //   12. Array of allowed values for small sets of string parameters (e.g. days of week).
        //   13. Parameter fuzzing exceptions - to tie to system alerts
        #endregion

        #region Detailed Notes for Possible Future Features

        //DATE FORMATTING:    ISO 8601 (yyyy-MM-dd'T'HH:mm:ssZ

        //   * USE ASYNC AND AWAIT* I guess. . . if you were doing I/O Bound or Network Bound stuff . . .  

        //SOURCE: https://stackoverflow.com/questions/6730009/validate-a-file-name-on-windows
        //        "  (?:\\.[^.]*)?                  # prevent dot dot?
        //^(?!^(PRN|AUX|CLOCK\$|NUL|CON|COM\d|LPT\d|\..*)(\..+)?$)[^\x00-\x1f\\?*:\"";|\/]+$

        //TODO: Support Filepath cleanse??? Leverage the below with added Regex parser?

        ///// <summary>
        ///// Cleans paths of invalid characters.
        ///// </summary>
        //public static class PathSanitizer
        //{
        //    /// <summary>
        //    /// The set of invalid path characters, kept sorted for fast binary search
        //    /// </summary>
        //    private readonly static char[] invalidPathChars;

        //    static PathSanitizer()
        //    {
        //        // set up the two arrays -- sorted once for speed.
        //        invalidPathChars = System.IO.Path.GetInvalidPathChars();
        //        Array.Sort(invalidPathChars);
        //    }

        //    /// <summary>
        //    /// Cleans a path of invalid characters
        //    /// </summary>
        //    /// <param name="input">the string to clean</param>
        //    /// <param name="errorChar">the character which replaces bad characters</param>
        //    /// <returns></returns>
        //    public static string SanitizePath(string input, char errorChar)
        //    {
        //        return Sanitize(input, invalidPathChars, errorChar);
        //    }

        //    /// <summary>
        //    /// Cleans a string of invalid characters.
        //    /// </summary>
        //    /// <param name="input"></param>
        //    /// <param name="invalidChars"></param>
        //    /// <param name="errorChar"></param>
        //    /// <returns></returns>
        //    private static string Sanitize(string input, char[] invalidChars, char errorChar)
        //    {
        //        // null always sanitizes to null
        //        if (input == null) { return null; }
        //        StringBuilder result = new StringBuilder();
        //        foreach (var characterToTest in input)
        //        {
        //            // we binary search for the character in the invalid set. This should be lightning fast.
        //            if (Array.BinarySearch(invalidChars, characterToTest) >= 0)
        //            {
        //                // we found the character in the array of 
        //                result.Append(errorChar);
        //            }
        //            else
        //            {
        //                // the character was not found in invalid, so it is valid.
        //                result.Append(characterToTest);
        //            }
        //        }

        //        // we're done.
        //        return result.ToString();
        //    }
        //}   

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

        ////SOURCE: https://github.com/microsoft/referencesource/blob/master/System.ComponentModel.DataAnnotations/DataAnnotations/Validator.cs
        //private static bool ValidateDataType(Type destinationType, object value)
        //{
        //    if (destinationType == null)
        //    {
        //        throw new ArgumentNullException("destinationType");
        //    }

        //    if (value == null)
        //    {
        //        // Null can be assigned only to reference types or Nullable or Nullable<>
        //        return !destinationType.IsValueType ||
        //                (destinationType.IsGenericType && destinationType.GetGenericTypeDefinition() == typeof(Nullable<>));
        //    }

        //    // Not null -- be sure it can be cast to the right type
        //    return destinationType.IsAssignableFrom(value.GetType());
        //}
        #endregion
    }
}
