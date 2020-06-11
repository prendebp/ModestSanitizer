using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

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

        public enum Approach
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
        public Approach SanitizerApproach { get; set; }
        public MinMax MinMax {get;set;}
        public Truncate Truncate { get; set; }
        public NormalizeOrLimit NormalizeOrLimit { get; set; }
        public FileNameCleanse FileNameCleanse { get; set; }
        public Whitelist Whitelist { get; set; }
        public Blacklist Blacklist { get; set; }
        public bool CompileRegex { get; set; }
        public Dictionary<Guid, KeyValuePair<SaniTypes, string>> SaniExceptions { get; set; }

        public Sanitizer(Approach sanitizerApproach, bool compileRegex) {
            SanitizerApproach = sanitizerApproach;
            if (sanitizerApproach == Approach.TrackExceptionsInList)
            {
                SaniExceptions = new Dictionary<Guid, KeyValuePair<SaniTypes, string>>();
            }
            CompileRegex = compileRegex;
            Truncate = new Truncate(SanitizerApproach, SaniExceptions);
            NormalizeOrLimit = new NormalizeOrLimit(Truncate, SanitizerApproach, SaniExceptions);
            MinMax = new MinMax(Truncate, NormalizeOrLimit, SanitizerApproach, CompileRegex, SaniExceptions);
            FileNameCleanse = new FileNameCleanse(Truncate, NormalizeOrLimit, SanitizerApproach, CompileRegex, SaniExceptions);
            Whitelist = new Whitelist(Truncate, NormalizeOrLimit, SanitizerApproach, SaniExceptions);
            Blacklist = new Blacklist(Truncate, NormalizeOrLimit, SanitizerApproach, SaniExceptions);
        }

        #region Detailed Notes for Possible Future Features


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


        //TODO: Support for SQL Injection Cleanse?

        //https://www.codementor.io/@satyaarya/prevent-sql-injection-attacks-in-net-ocfxkhnyf
        //how to detect and/or prevent hexadecimal/binary/decimal? Octal?

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
        #endregion
    }
}
