using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static ModestSanitizer.Sanitizer;

namespace ModestSanitizer
{
    /// <summary>
    ///  Blacklist = 7
    ///  Throw exception on blacklist values (optional and un-advised, whitelist is better)
    //   Why? To assist with blacklisting potential malicious input
    /// </summary>
    public class Blacklist
    {
        public Truncate Truncate { get; set; }

        public NormalizeOrLimit NormalizeOrLimit { get; set; }
        public SaniApproach SanitizerApproach { get; set; }
        public Dictionary<Guid, KeyValuePair<SaniTypes, string>> SaniExceptions { get; set; }

        public Blacklist()
        {
        }

        public Blacklist(SaniApproach sanitizerApproach)
        {
            SanitizerApproach = sanitizerApproach;
        }

        public Blacklist(Truncate truncate, NormalizeOrLimit normalizeOrLimit, SaniApproach sanitizerApproach, Dictionary<Guid, KeyValuePair<SaniTypes, string>> saniExceptions) : this(sanitizerApproach)
        {
            Truncate = truncate;
            NormalizeOrLimit = normalizeOrLimit;
            SaniExceptions = saniExceptions;
        }

        public static List<string> GenerateHexadecimalBlacklist()
        {
            List<string> hexBlacklist = new List<string>();
            hexBlacklist.Add(@"%%");
            hexBlacklist.Add(@"%p");
            hexBlacklist.Add(@"%d");
            hexBlacklist.Add(@"%c");
            hexBlacklist.Add(@"%u");
            hexBlacklist.Add(@"%x");
            hexBlacklist.Add(@"%s");
            hexBlacklist.Add(@"%n");
            hexBlacklist.Add(@"\x");

            return hexBlacklist;
        }
        public static List<string> GenerateCommonBlacklist()
        {
            List<string> commonBlacklist = new List<string>();

            commonBlacklist.Add(@"\0"); //replace null byte with empty string
            commonBlacklist.Add(@"\u00A0"); //replace non-breaking space with empty string. Regular space U+0020 would be allowed.
            commonBlacklist.Add(@"\u2B7E"); //replace tab with empty string
            commonBlacklist.Add(@"\u000A"); //replace new line with empty string
            commonBlacklist.Add(@"\u000D"); //replace carriage return with empty string
            commonBlacklist.Add(@"\u2B7F");//replace vertical tab with empty string
            //commonBlacklist.Add(@"\u005C"); //replace reverse solidus or backslash with empty string
            commonBlacklist.Add(@"\u200B"); //replace zero-width space character with empty string
            commonBlacklist.Add(@"\u2009"); //replace thin space with empty string
            commonBlacklist.Add(@"\u007F"); //replace delete with empty string
            //commonBlacklist.Add(@"\u007E"); //replace tilde with empty string
            commonBlacklist.Add(@"\u0000"); //replace null byte with empty string
            commonBlacklist.Add(@"\u202E"); //replace Left-To-Right with empty string
            commonBlacklist.Add(@"\u200F"); //replace Right-To-Left with empty string
            commonBlacklist.Add(@"% 00"); //alert on common examples of null bytes used on hacking sites
            commonBlacklist.Add(@"%00"); //alert on common examples of null bytes used on hacking sites
            commonBlacklist.Add(@"\t"); //replace tab with empty string
            commonBlacklist.Add(@"\n"); //replace new line with empty string
            commonBlacklist.Add(@"\r"); //replace carriage return with empty string
            commonBlacklist.Add(@"\v");//replace vertical tab with empty string
               
            return commonBlacklist;
        }

        //TODO: Fill-in new methods here for blacklist of OS Commands or SQL Injection keywords?
        /// <summary>
        /// Review - compare string to check against blacklist value while ignoring case
        /// </summary>
        /// <param name="stringToCheck"></param>
        /// <returns></returns>   
        public bool? ReviewIgnoreCaseUsingASCII(string stringToCheck, List<string> blacklistValues, int lengthToTruncateTo, bool checkForHexChars = true, bool checkForCommonMaliciousChars = true)
        {
            bool? tmpResult = false;
            StringComparison ic = StringComparison.InvariantCultureIgnoreCase;//be more inclusive for blacklist

            try
            {
                if (blacklistValues == null || blacklistValues.Count == 0)
                {
                    throw new Exception("Blacklist value cannot be null or empty list!");
                }  

                if (String.IsNullOrWhiteSpace(stringToCheck))
                {
                    tmpResult = null;
                }
                else
                {
                    if (checkForCommonMaliciousChars == true)
                    {
                        //Review in Unicode instead of ASCII for this case since the common malicious characters are listed mostly in unicode chars
                        string normalizedString = NormalizeOrLimit.NormalizeUnicode(stringToCheck);
                        string truncatedString = Truncate.TruncateToValidLength(normalizedString, lengthToTruncateTo);

                        int initialLengthStr = truncatedString.Length;
                        string strPostReplacement = String.Empty;
                        bool hasMaliciousChars = false;

                        foreach (string badVal in GenerateCommonBlacklist())
                        {
                            strPostReplacement = Replace(truncatedString, badVal, string.Empty, ic);
                            if (strPostReplacement.Length < initialLengthStr) //new length will be shorter since blacklist chars replaced
                            {
                                hasMaliciousChars = true;
                            }
                        }

                        if (hasMaliciousChars)
                        {
                            throw new Exception("StringToCheck contains a common malicious character.");
                        }
                        else
                        {
                            tmpResult = false;
                        }
                    }

                    if (checkForHexChars == true)
                    {
                        List<string> hexBlacklist = Blacklist.GenerateHexadecimalBlacklist();
                        hexBlacklist.AddRange(blacklistValues); //check for hex values first before the developer-defined blacklist to avoid tainting
                        blacklistValues = hexBlacklist;
                    }

                    string limitedToASCII = NormalizeOrLimit.LimitToASCIIOnly(stringToCheck);
                    string truncatedValue = Truncate.TruncateToValidLength(limitedToASCII, lengthToTruncateTo);
                   
                    int initialLength = truncatedValue.Length;
                    string stringPostReplacement = String.Empty;
                    bool isSuccess = false;

                    foreach (string badVal in blacklistValues) 
                    {
                        stringPostReplacement = Replace(truncatedValue, badVal, string.Empty, ic);
                        if (stringPostReplacement.Length < initialLength) //new length will be shorter since blacklist chars replaced
                        {
                            isSuccess = true;
                        }
                    }

                    if (isSuccess)
                    {
                        throw new Exception("StringToCheck contains a blacklist value.");
                    }
                    else
                    {
                        tmpResult = false;
                    }
                }
            }
            catch (Exception ex)
            {
                TrackOrThrowException("Issue with Blacklist ReviewIgnoreCase method", stringToCheck, ex);
            }
            return tmpResult;
        }

        //SOURCE: https://stackoverflow.com/questions/6275980/string-replace-ignoring-case
        private static string Replace(string str, string old, string @new, StringComparison comparison)
        {
            @new = @new ?? "";
            if (string.IsNullOrEmpty(str) || string.IsNullOrEmpty(old) || old.Equals(@new, comparison))
                return str;
            int foundAt = 0;
            while ((foundAt = str.IndexOf(old, foundAt, comparison)) != -1)
            {
                str = str.Remove(foundAt, old.Length).Insert(foundAt, @new);
                foundAt += @new.Length;
            }
            return str;
        }

        private void TrackOrThrowException(string msg, string valToClean, Exception ex)
        {
            string exceptionValue = Truncate.TruncateToValidLength(valToClean, 5);

            if (SanitizerApproach == SaniApproach.TrackExceptionsInList)
            {
                SaniExceptions.Add(Guid.NewGuid(), new KeyValuePair<SaniTypes, string>(SaniTypes.Blacklist, exceptionValue));
            }
            else
            {
                throw new SanitizerException(msg + (exceptionValue ?? String.Empty), ex);
            }
        }
    }//end of class
}//end of namespace
