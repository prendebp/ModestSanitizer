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
    ///  RestrictedList = 7
    ///  Throw exception on restrictedList values (for monitoring/cleansing, un-advised by itself, allowedList is better)
    //   Why? To assist with restrictedListing potential malicious input
    /// </summary>
    public class RestrictedList
    {
        public enum RestrictedListType
        {
            None = 0,
            All = 1,
            OSCommandInjection = 2,
            FormatStringAttacks = 3
        }

        private SaniCore SaniCore { get; set; }

        private int TruncateLength { get; set; }
        private SaniTypes SaniType { get; set; }
        
        public RestrictedList(SaniCore saniCore)
        {
            SaniCore = saniCore;

            TruncateLength = 10;
            SaniType = SaniTypes.RestrictedList;
        }

        //Why check for Hexadecimal? 
        //To protect against format string attacks with unsafe keyword: https://owasp.org/www-community/attacks/Format_string_attack
        public static List<string> GenerateHexAndEscapeSeqRestrictedList()
        {
            //NOTE: @"\ resolves to this \\. Without the asterisk "\ will resolve to \. So, we will duplicate to check both ways.
            List<string> hexRestrictedList = new List<string>
            {
                @"%%", //detect hexadecimal
                @"%p", //detect hexadecimal
                @"%d", //detect hexadecimal
                @"%c", //detect hexadecimal
                @"%u", //detect hexadecimal
                @"%x", //detect hexadecimal
                @"%s", //detect hexadecimal
                @"%n", //detect hexadecimal               
                @"\x", //detect hexadecimal
                @"\\x",//detect hexadecimal
                @"0o", //detect if trying to use Octal. C# does not support octal literal but monitor attempts.
                @"\\0",//detect if trying to use Octal. C# does not support octal literal but monitor attempts.
                @"\\1",//detect if trying to use Octal. C# does not support octal literal but monitor attempts.
                @"\0", //detect if trying to use Octal. C# does not support octal literal but monitor attempts.
                @"\1",//detect if trying to use Octal. C# does not support octal literal but monitor attempts.
                @"\\c",//detect if trying to use Octal. C# does not support octal literal but monitor attempts.
                @"\c",//detect if trying to use Octal. C# does not support octal literal but monitor attempts.
                @"\\3",//detect if trying to use Octal. C# does not support octal literal but monitor attempts.
                @"\3", //detect if trying to use Octal. C# does not support octal literal but monitor attempts.
                @"\'", //detect sinqle quote
                @"\""",//detect double quote
                @"\a", //replace alert with empty string
                @"\t", //replace tab with empty string
                @"\n", //replace new line with empty string
                @"\r", //replace carriage return with empty string
                @"\v", //replace vertical tab with empty string
                @"\b", //replace backspace with empty string
                @"\f", //replace form feed with empty string
                @"{{", //replace double curly braces with empty string
                "%%", //detect hexadecimal
                "%p", //detect hexadecimal
                "%d", //detect hexadecimal
                "%c", //detect hexadecimal
                "%u", //detect hexadecimal
                "%x", //detect hexadecimal
                "%s", //detect hexadecimal
                "%n", //detect hexadecimal  
                "\\x",//detect hexadecimal
                "0o", //detect if trying to use Octal. C# does not support octal literal but monitor attempts.
                "\\0",//detect if trying to use Octal. C# does not support octal literal but monitor attempts.
                "\\1",//detect if trying to use Octal. C# does not support octal literal but monitor attempts.
                "\0", //detect if trying to use Octal. C# does not support octal literal but monitor attempts.
                "\\c",//detect if trying to use Octal. C# does not support octal literal but monitor attempts.
                "\\3",//detect if trying to use Octal. C# does not support octal literal but monitor attempts.
                "\'", //detect sinqle quote
                "\"\"",//detect double quote
                "\a", //replace alert with empty string
                "\t", //replace tab with empty string
                "\n", //replace new line with empty string
                "\r", //replace carriage return with empty string
                "\v", //replace vertical tab with empty string
                "\b", //replace backspace with empty string
                "\f", //replace form feed with empty string
                "{{", //replace double curly braces with empty string
            };

            return hexRestrictedList;
        }
        public static List<string> GenerateCommonRestrictedList()
        {
            //NOTE: @"\ resolves to this \\. Without the asterisk "\ will resolve to \. So, we will duplicate to check both ways.
            List<string> commonRestrictedList = new List<string>
            {  
                @"\x0", //replace null byte with empty string. C# string can contain any number of embedded null characters ('\0')
                @"\0",  //replace null byte with empty string. C# string can contain any number of embedded null characters ('\0')
                @"\u00A0", //replace non-breaking space with empty string. Regular space U+0020 would be allowed.
                @"\u2B7E", //replace tab with empty string
                @"\u000A", //replace new line with empty string
                @"\u000D", //replace carriage return with empty string
                @"\u2B7F",//replace vertical tab with empty string
                          //commonRestrictedList.Add(@"\u005C"); //replace reverse solidus or backslash with empty string. File path may allow.
                @"\u200B", //replace zero-width space character with empty string
                @"\u2009", //replace thin space with empty string
                @"\u007F", //replace delete with empty string
                           //commonRestrictedList.Add(@"\u007E"); //replace tilde with empty string. File path may allow.
                @"\u0000", //replace null byte with empty string
                @"\u202E", //replace Left-To-Right with empty string
                @"\u200F", //replace Right-To-Left with empty string
                @"% 00", //alert on common examples of null bytes used on hacking sites
                @"%00", //alert on common examples of null bytes used on hacking sites
                "\x0", //replace null byte with empty string. C# string can contain any number of embedded null characters ('\0')
                "\0",  //replace null byte with empty string. C# string can contain any number of embedded null characters ('\0')
                "\u00A0", //replace non-breaking space with empty string. Regular space U+0020 would be allowed.
                "\u2B7E", //replace tab with empty string
                "\u000A", //replace new line with empty string
                "\u000D", //replace carriage return with empty string
                "\u2B7F",//replace vertical tab with empty string
                          //commonRestrictedList.Add(@"\u005C"); //replace reverse solidus or backslash with empty string. File path may allow.
                "\u200B", //replace zero-width space character with empty string
                "\u2009", //replace thin space with empty string
                "\u007F", //replace delete with empty string
                           //commonRestrictedList.Add(@"\u007E"); //replace tilde with empty string. File path may allow.
                "\u0000", //replace null byte with empty string
                "\u202E", //replace Left-To-Right with empty string
                "\u200F", //replace Right-To-Left with empty string
                "% 00", //alert on common examples of null bytes used on hacking sites
                "%00", //alert on common examples of null bytes used on hacking sites
                "\uFFFD" //replace U+FFFD REPLACEMENT CHARACTER ('�') with empty string
            };

            return commonRestrictedList;
        }

        //TODO: Fill-in new methods here for restrictedList of OS Commands or SQL Injection keywords?
        /// <summary>
        /// Review - compare string to check against restrictedList value while ignoring case. Returns true if any issue or restrictedList match found. stringToCheck will be cleansed.
        /// </summary>
        /// <param name="stringToCheck"></param>
        /// <returns></returns>   
        public bool? ReviewIgnoreCaseUsingASCII(ref string stringToCheck, List<string> restrictedListValues, int lengthToTruncateTo, bool checkForHexChars = true, bool checkForCommonMaliciousChars = true)
        {
            bool? tmpResult = false;
            StringComparison ic = StringComparison.InvariantCultureIgnoreCase;//be more inclusive for restrictedList
            bool hasCommonMaliciousChars = false;
            bool hasOtherMaliciousChars = false;

            try
            {
                if (restrictedListValues == null || restrictedListValues.Count == 0)
                {
                    tmpResult = true;
                    throw new Exception("RestrictedList value cannot be null or empty list!");
                }  

                if (String.IsNullOrWhiteSpace(stringToCheck))
                {
                    tmpResult = null; //Always return null. Protects against a gigabyte of whitespace!!!
                }
                else
                {
                    if (checkForCommonMaliciousChars == true)
                    {
                        //Review in Unicode instead of ASCII for this case since the common malicious characters are listed mostly in unicode chars
                        
                        string truncatedString = SaniCore.Truncate.ToValidLength(stringToCheck, lengthToTruncateTo);
                        string normalizedString = SaniCore.NormalizeOrLimit.NormalizeUnicode(truncatedString);

                        int initialLengthStr = normalizedString.Length;
                        string strPostReplacement = String.Empty;
                        
                        bool firstPass = true;

                        foreach (string badVal in GenerateCommonRestrictedList())
                        {
                            if (firstPass == true)
                            {
                                strPostReplacement = Replace(normalizedString, badVal, string.Empty, ic);
                                firstPass = false;
                            }
                            else
                            {
                                strPostReplacement = Replace(strPostReplacement, badVal, string.Empty, ic);
                            }

                            if (strPostReplacement.Length < initialLengthStr) //new length will be shorter since restrictedList chars replaced
                            {
                                hasCommonMaliciousChars = true;
                            }
                        }

                        if (hasCommonMaliciousChars)
                        {
                            tmpResult = true;
                            stringToCheck = strPostReplacement;

                            //FIRE THIS LATER: throw new Exception("StringToCheck contains a common malicious character.");
                        }
                        else
                        {
                            tmpResult = false;
                        }
                    }

                    if (checkForHexChars == true)
                    {
                        List<string> hexRestrictedList = RestrictedList.GenerateHexAndEscapeSeqRestrictedList();

                        //Check for hex values first before the developer - defined restrictedList to avoid tainting
                        hexRestrictedList.AddRange(restrictedListValues); //Add restricted values to the end
                        restrictedListValues = hexRestrictedList;
                    }

                    string truncatedValue = SaniCore.Truncate.ToValidLength(stringToCheck, lengthToTruncateTo);
                    string limitedToASCII = SaniCore.NormalizeOrLimit.ToASCIIOnly(truncatedValue);
                                       
                    int initialLength = limitedToASCII.Length;
                    string stringPostReplacement = String.Empty;

                    bool firstPassAgain = true; 
                    foreach (string badVal in restrictedListValues)
                    {
                        if (firstPassAgain == true)
                        {
                            stringPostReplacement = Replace(limitedToASCII, badVal, string.Empty, ic);
                            firstPassAgain = false;
                        }
                        else
                        {
                            stringPostReplacement = Replace(stringPostReplacement, badVal, string.Empty, ic);
                        }
                        
                        if (stringPostReplacement.Length < initialLength) //new length will be shorter since restrictedList chars replaced
                        {
                            hasOtherMaliciousChars = true;
                        }
                    }

                    if (hasOtherMaliciousChars)
                    {
                        tmpResult = true;

                        stringToCheck = stringPostReplacement;

                        if (hasCommonMaliciousChars)
                        {
                            throw new Exception("StringToCheck contains a common malicious character and a restrictedList value.");
                        }
                        else
                        {
                            throw new Exception("StringToCheck contains a restrictedList value.");
                        }
                    }
                    else
                    {
                        if (hasCommonMaliciousChars)
                        {
                            throw new Exception("StringToCheck contains a common malicious character.");
                        }

                        //if once tmpResult has been set to true, do NOT un-set tmpResult to false
                    }
                }
            }
            catch (Exception ex)
            {
                tmpResult = true;
                SaniExceptionHandler.TrackOrThrowException(TruncateLength, SaniType, SaniCore, "RestrictedList: ", "Issue with RestrictedList ReviewIgnoreCase method", stringToCheck, ex);
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

    }//end of class
}//end of namespace
