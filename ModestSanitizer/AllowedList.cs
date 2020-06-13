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
    ///  AllowedList = 4
    ///  Check allowedList of valid values using ASCII or Unicode
    //   Why? To safely compare input string(s) to expected, valid values
    /// </summary>
    public class AllowedList
    {
        private SaniCore SaniCore { get; set; }

        private int TruncateLength { get; set; }
        private SaniTypes SaniType { get; set; }


        public UsingASCII ASCII { get; set; }
        public UsingUnicode Unicode { get; set; }

        public AllowedList(SaniCore saniCore)
        {
            SaniCore = saniCore;

            TruncateLength = 10;
            SaniType = SaniTypes.AllowedList;

            ASCII = new UsingASCII(saniCore);
            Unicode = new UsingUnicode(saniCore);
        }

        public class UsingASCII
        {
            private SaniCore SaniCore { get; set; }

            private int TruncateLength { get; set; }
            private SaniTypes SaniType { get; set; }

            public UsingASCII(SaniCore saniCore)
            {
                SaniCore = saniCore;

                TruncateLength = 10;
                SaniType = SaniTypes.AllowedList;
            }

            /// <summary>
            /// Matches - compare string to check against allowedList value. Sets stringToCheck to allowedList value if equivalent.
            /// </summary>
            /// <param name="stringToCheck"></param>
            /// <returns></returns>   
            public bool? Matches(ref string stringToCheck, string allowedListValue, int lengthToTruncateTo)
            {
                bool? tmpResult = false;

                try
                {
                    if (String.IsNullOrWhiteSpace(allowedListValue))
                    {
                        throw new Exception("AllowedList value cannot be null or empty!");
                    }

                    if (String.IsNullOrWhiteSpace(stringToCheck))
                    {
                        tmpResult = null;
                    }
                    else
                    {
                        string limitedToASCII = SaniCore.NormalizeOrLimit.ToASCIIOnly(stringToCheck);
                        string truncatedValue = SaniCore.Truncate.ToValidLength(limitedToASCII, lengthToTruncateTo);
                        bool isSuccess = (truncatedValue.Equals(allowedListValue));

                        if (isSuccess)
                        {
                            stringToCheck = allowedListValue;
                            tmpResult = true;
                        }
                        else
                        {
                            throw new Exception("StringToCheck does NOT match allowedList value.");
                        }
                    }
                }
                catch (Exception ex)
                {
                    SaniExceptionHandler.TrackOrThrowException(TruncateLength, SaniType, SaniCore, "AllowedList: ", "Issue with AllowedList ASCII Matches method", stringToCheck, ex);
                }
                return tmpResult;
            }

            /// <summary>
            /// MatchesIgnoreCase - compare string to check against allowedList value while ignoring case sensitivity. Sets stringToCheck to allowedList value (including case) if matched.
            /// </summary>
            /// <param name="stringToCheck"></param>
            /// <returns></returns>   
            public bool? MatchesIgnoreCase(ref string stringToCheck, string allowedListValue, int lengthToTruncateTo)
            {
                bool? tmpResult = false;

                try
                {
                    if (String.IsNullOrWhiteSpace(allowedListValue))
                    {
                        throw new Exception("AllowedList value cannot be null or empty!");
                    }

                    if (String.IsNullOrWhiteSpace(stringToCheck))
                    {
                        tmpResult = null;
                    }
                    else
                    {
                        string truncatedValue = SaniCore.Truncate.ToValidLength(stringToCheck, lengthToTruncateTo);
                        string limitedToASCII = SaniCore.NormalizeOrLimit.ToASCIIOnly(truncatedValue);
                        StringComparison ic = StringComparison.OrdinalIgnoreCase;

                        int initialLength = limitedToASCII.Length;
                        string stringPostReplacement = Replace(limitedToASCII, allowedListValue, string.Empty, ic);
                        int finalLength = stringPostReplacement.Length;

                        bool isSuccess = (finalLength == 0);

                        if (isSuccess)
                        {
                            stringToCheck = allowedListValue;
                            tmpResult = true;
                        }
                        else
                        {
                            throw new Exception("StringToCheck does NOT match allowedList value.");
                        }
                    }
                }
                catch (Exception ex)
                {
                    SaniExceptionHandler.TrackOrThrowException(TruncateLength, SaniType, SaniCore, "AllowedList: ", "Issue with AllowedList ASCII MatchesIgnoreCase method", stringToCheck, ex);
                }
                return tmpResult;
            }
        }

        public class UsingUnicode
        {
            private SaniCore SaniCore { get; set; }

            private int TruncateLength { get; set; }
            private SaniTypes SaniType { get; set; }

            public UsingUnicode(SaniCore saniCore)
            {
                SaniCore = saniCore;

                TruncateLength = 10;
                SaniType = SaniTypes.AllowedList;
            }

            /// <summary>
            /// Matches - compare string to check against allowedList value. Sets stringToCheck to allowedList value if equivalent.
            /// </summary>
            /// <param name="stringToCheck"></param>
            /// <returns></returns>   
            public bool? Matches(ref string stringToCheck, string allowedListValue, int lengthToTruncateTo)
            {
                bool? tmpResult = false;

                try
                {
                    if (String.IsNullOrWhiteSpace(allowedListValue))
                    {
                        throw new Exception("AllowedList value cannot be null or empty!");
                    }

                    if (String.IsNullOrWhiteSpace(stringToCheck))
                    {
                        tmpResult = null;
                    }
                    else
                    {
                        string normalizedUnicode = SaniCore.NormalizeOrLimit.NormalizeUnicode(stringToCheck);
                        string truncatedValue = SaniCore.Truncate.ToValidLength(normalizedUnicode, lengthToTruncateTo);
                        bool isSuccess = (truncatedValue.Equals(allowedListValue));

                        if (isSuccess)
                        {
                            stringToCheck = allowedListValue;
                            tmpResult = true;
                        }
                        else
                        {
                            throw new Exception("StringToCheck does NOT match allowedList value.");
                        }
                    }
                }
                catch (Exception ex)
                {
                    SaniExceptionHandler.TrackOrThrowException(TruncateLength, SaniType, SaniCore, "AllowedList: ", "Issue with AllowedList Unicode Matches method", stringToCheck, ex);
                }
                return tmpResult;
            }

            /// <summary>
            /// MatchesIgnoreCase - compare string to check against allowedList value while ignoring case sensitivity. Sets stringToCheck to allowedList value (including case) if matched.
            /// </summary>
            /// <param name="stringToCheck"></param>
            /// <returns></returns>   
            public bool? MatchesIgnoreCase(ref string stringToCheck, string allowedListValue, int lengthToTruncateTo)
            {
                bool? tmpResult = false;

                try
                {
                    if (String.IsNullOrWhiteSpace(allowedListValue))
                    {
                        throw new Exception("AllowedList value cannot be null or empty!");
                    }

                    if (String.IsNullOrWhiteSpace(stringToCheck))
                    {
                        tmpResult = null;
                    }
                    else
                    {
                        string truncatedValue = SaniCore.Truncate.ToValidLength(stringToCheck, lengthToTruncateTo);
                        string normalizedUnicode = SaniCore.NormalizeOrLimit.NormalizeUnicode(truncatedValue);
                        StringComparison ic = StringComparison.OrdinalIgnoreCase;
                        bool isSuccess = (normalizedUnicode.Equals(allowedListValue, ic));

                        if (isSuccess)
                        {
                            stringToCheck = allowedListValue;
                            tmpResult = true;
                        }
                        else
                        {
                            throw new Exception("StringToCheck does NOT match allowedList value.");
                        }
                    }
                }
                catch (Exception ex)
                {
                    SaniExceptionHandler.TrackOrThrowException(TruncateLength, SaniType, SaniCore, "AllowedList: ", "Issue with AllowedList Unicode MatchesIgnoreCase method", stringToCheck, ex);
                }
                return tmpResult;
            }
        }

        //TODO: partial allowedList such as the domain of an email address? ^[a-zA-Z0-9_+&*-]+(?:\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,7}$

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
