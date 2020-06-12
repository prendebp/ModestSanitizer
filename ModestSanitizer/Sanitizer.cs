using System;
using System.Collections.Generic;
using static ModestSanitizer.SaniCore;

namespace ModestSanitizer
{
    /// <summary>
    /// REASONABLY SECURE GENERAL PURPOSE LIBRARY TO SANITIZE INPUT THAT DOES NOT REQUIRE OUTPUT ENCODING.
    /// For output encoding see Anti-XSS.
    //  For LDAP encoding see Anti-XSS.
    /// </summary>
    public class Sanitizer
    {
        public enum SaniTypes
        {
            None = 0,
            MinMax = 1,
            Truncate = 2,
            NormalizeOrLimit = 3,
            Whitelist = 4,
            SQLInjection = 5,
            FileNameCleanse = 6,
            Blacklist = 7
        }

        public SaniCore SaniCore { get; set; }

        public Truncate Truncate { get; set; }
        public Blacklist Blacklist { get; set; }
        public MinMax MinMax { get; set; }
        public NormalizeOrLimit NormalizeOrLimit { get; set; }
        public FileNameCleanse FileNameCleanse { get; set; }
        public Whitelist Whitelist { get; set; }

        public Approach SanitizerApproach { get; set; }
        public Dictionary<Guid, KeyValuePair<SaniTypes, string>> SaniExceptions { get; set; }

        public Sanitizer(Approach sanitizerApproach, bool compileRegex) {

            SaniCore = new SaniCore();
            SaniCore.SanitizerApproach = sanitizerApproach;
            SanitizerApproach = SaniCore.SanitizerApproach;

            SaniCore.SaniExceptions = new Dictionary<Guid, KeyValuePair<SaniTypes, string>>();
            SaniExceptions = SaniCore.SaniExceptions;

            SaniCore.CompileRegex = compileRegex;
            SaniCore.Truncate = new Truncate(SaniCore);
            Truncate = SaniCore.Truncate;
            SaniCore.NormalizeOrLimit = new NormalizeOrLimit(SaniCore);
            NormalizeOrLimit = SaniCore.NormalizeOrLimit;
            SaniCore.MinMax = new MinMax(SaniCore);
            MinMax = SaniCore.MinMax;
            SaniCore.FileNameCleanse = new FileNameCleanse(SaniCore);
            FileNameCleanse = SaniCore.FileNameCleanse;
            SaniCore.Whitelist = new Whitelist(SaniCore);
            Whitelist = SaniCore.Whitelist;
            SaniCore.Blacklist = new Blacklist(SaniCore);
            Blacklist = SaniCore.Blacklist;
        }

        /// <summary>
        /// For security purposes, clear the SaniExceptions when done sanitizing since these could store strings that you've cleansed
        /// </summary>
        public void ClearSaniExceptions() 
        {
            SaniCore.SaniExceptions.Clear();
        }

        #region Detailed Notes for Possible Future Features


        //TODO: Support Filepath cleanse??? Leverage the below with added Regex parser?

        //how to handle @"\\", backslash escape character safely?

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
