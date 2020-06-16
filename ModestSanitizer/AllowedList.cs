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
            /// StartsWithPrefix - compare string to check against allowedList value at the start of the string.
            /// </summary>
            /// <param name="stringToCheck"></param>
            /// <returns></returns>   
            public bool? StartsWithPrefix(ref string stringToCheck, string allowedListPrefix, int lengthToTruncateTo)
            {
                bool? tmpResult = false;

                try
                {
                    if (String.IsNullOrWhiteSpace(allowedListPrefix))
                    {
                        throw new Exception("AllowedList prefix cannot be null or empty!");
                    }

                    if (String.IsNullOrWhiteSpace(stringToCheck))
                    {
                        tmpResult = null; //Always return null. Protects against a gigabyte of whitespace!!!
                    }
                    else
                    {
                        StringComparison ord = StringComparison.Ordinal;

                        //Truncate first to lean towards more conservative. Have to pass in string in FormKC format.
                        string truncatedValue = SaniCore.Truncate.ToValidLength(stringToCheck, lengthToTruncateTo);
                        string limitedToASCII = SaniCore.NormalizeOrLimit.ToASCIIOnly(truncatedValue);
                       
                        bool isSuccess = (limitedToASCII.StartsWith(allowedListPrefix, ord));

                        if (isSuccess)
                        {
                            stringToCheck = limitedToASCII;
                            tmpResult = true;
                        }
                        else
                        {
                            throw new Exception("StringToCheck does NOT start with the allowedList prefix.");
                        }
                    }
                }
                catch (Exception ex)
                {
                    SaniExceptionHandler.TrackOrThrowException(TruncateLength, SaniType, SaniCore, "AllowedList: ", "Issue with AllowedList ASCII StartsWithPrefix method", stringToCheck, ex);
                }
                return tmpResult;
            }

            /// <summary>
            /// EndsWithSuffix - compare string to check against allowedList value at the end of the string.
            /// </summary>
            /// <param name="stringToCheck"></param>
            /// <returns></returns>   
            public bool? EndsWithSuffix(ref string stringToCheck, string allowedListSuffix, int lengthToTruncateTo)
            {
                bool? tmpResult = false;

                try
                {
                    if (String.IsNullOrWhiteSpace(allowedListSuffix))
                    {
                        throw new Exception("AllowedList Suffix cannot be null or empty!");
                    }

                    if (String.IsNullOrWhiteSpace(stringToCheck))
                    {
                        tmpResult = null; //Always return null. Protects against a gigabyte of whitespace!!!
                    }
                    else
                    {
                        StringComparison ord = StringComparison.Ordinal;

                        //Truncate first to lean towards more conservative. Have to pass in string in FormKC format.
                        string truncatedValue = SaniCore.Truncate.ToValidLength(stringToCheck, lengthToTruncateTo);
                        string limitedToASCII = SaniCore.NormalizeOrLimit.ToASCIIOnly(truncatedValue);

                        bool isSuccess = (limitedToASCII.EndsWith(allowedListSuffix, ord));

                        if (isSuccess)
                        {
                            stringToCheck = limitedToASCII;
                            tmpResult = true;
                        }
                        else
                        {
                            throw new Exception("StringToCheck does NOT end with the allowedList Suffix.");
                        }
                    }
                }
                catch (Exception ex)
                {
                    SaniExceptionHandler.TrackOrThrowException(TruncateLength, SaniType, SaniCore, "AllowedList: ", "Issue with AllowedList ASCII EndsWithSuffix method", stringToCheck, ex);
                }
                return tmpResult;
            }

            /// <summary>
            /// StartsWithPrefixIgnoreCase - compare string to check against allowedList value at the start of the string ignoring case.
            /// </summary>
            /// <param name="stringToCheck"></param>
            /// <returns></returns>   
            public bool? StartsWithPrefixIgnoreCase(ref string stringToCheck, string allowedListPrefix, int lengthToTruncateTo)
            {
                bool? tmpResult = false;

                try
                {
                    if (String.IsNullOrWhiteSpace(allowedListPrefix))
                    {
                        throw new Exception("AllowedList prefix cannot be null or empty!");
                    }

                    if (String.IsNullOrWhiteSpace(stringToCheck))
                    {
                        tmpResult = null; //Always return null. Protects against a gigabyte of whitespace!!!
                    }
                    else
                    {
                        StringComparison ic = StringComparison.OrdinalIgnoreCase;

                        //Truncate first to lean towards more conservative. Have to pass in string in FormKC format.
                        string truncatedValue = SaniCore.Truncate.ToValidLength(stringToCheck, lengthToTruncateTo);
                        string limitedToASCII = SaniCore.NormalizeOrLimit.ToASCIIOnly(truncatedValue);

                        bool isSuccess = (limitedToASCII.StartsWith(allowedListPrefix, ic));

                        if (isSuccess)
                        {
                            stringToCheck = limitedToASCII;
                            tmpResult = true;
                        }
                        else
                        {
                            throw new Exception("StringToCheck does NOT start with the allowedList prefix while ignoring case.");
                        }
                    }
                }
                catch (Exception ex)
                {
                    SaniExceptionHandler.TrackOrThrowException(TruncateLength, SaniType, SaniCore, "AllowedList: ", "Issue with AllowedList ASCII StartsWithPrefixIgnoreCase method", stringToCheck, ex);
                }
                return tmpResult;
            }

            /// <summary>
            /// EndsWithSuffixIgnoreCase - compare string to check against allowedList value at the end of the string ignoring case.
            /// </summary>
            /// <param name="stringToCheck"></param>
            /// <returns></returns>   
            public bool? EndsWithSuffixIgnoreCase(ref string stringToCheck, string allowedListSuffix, int lengthToTruncateTo)
            {
                bool? tmpResult = false;

                try
                {
                    if (String.IsNullOrWhiteSpace(allowedListSuffix))
                    {
                        throw new Exception("AllowedList Suffix cannot be null or empty!");
                    }

                    if (String.IsNullOrWhiteSpace(stringToCheck))
                    {
                        tmpResult = null; //Always return null. Protects against a gigabyte of whitespace!!!
                    }
                    else
                    {
                        StringComparison ic = StringComparison.OrdinalIgnoreCase;

                        //Truncate first to lean towards more conservative. Have to pass in string in FormKC format.
                        string truncatedValue = SaniCore.Truncate.ToValidLength(stringToCheck, lengthToTruncateTo);
                        string limitedToASCII = SaniCore.NormalizeOrLimit.ToASCIIOnly(truncatedValue);

                        bool isSuccess = (limitedToASCII.EndsWith(allowedListSuffix, ic));

                        if (isSuccess)
                        {
                            stringToCheck = limitedToASCII;
                            tmpResult = true;
                        }
                        else
                        {
                            throw new Exception("StringToCheck does NOT start with the allowedList Suffix while ignoring case.");
                        }
                    }
                }
                catch (Exception ex)
                {
                    SaniExceptionHandler.TrackOrThrowException(TruncateLength, SaniType, SaniCore, "AllowedList: ", "Issue with AllowedList ASCII EndsWithSuffixIgnoreCase method", stringToCheck, ex);
                }
                return tmpResult;
            }

            /// <summary>
            /// EqualsValue - compare string to check against allowedList value. Sets stringToCheck to allowedList value if equivalent.
            /// </summary>
            /// <param name="stringToCheck"></param>
            /// <returns></returns>   
            public bool? EqualsValue(ref string stringToCheck, string allowedListValue, int lengthToTruncateTo)
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
                        tmpResult = null; //Always return null. Protects against a gigabyte of whitespace!!!
                    }
                    else
                    {
                        //Truncate first to lean towards more conservative. Have to pass in string in FormKC format.
                        string truncatedValue = SaniCore.Truncate.ToValidLength(stringToCheck, lengthToTruncateTo);
                        string limitedToASCII = SaniCore.NormalizeOrLimit.ToASCIIOnly(truncatedValue);
                        
                        bool isSuccess = (limitedToASCII.Equals(allowedListValue));

                        if (isSuccess)
                        {
                            stringToCheck = allowedListValue;
                            tmpResult = true;
                        }
                        else
                        {
                            throw new Exception("StringToCheck does NOT equal allowedList value.");
                        }
                    }
                }
                catch (Exception ex)
                {
                    SaniExceptionHandler.TrackOrThrowException(TruncateLength, SaniType, SaniCore, "AllowedList: ", "Issue with AllowedList ASCII EqualsValue method", stringToCheck, ex);
                }
                return tmpResult;
            }

            /// <summary>
            /// EqualsValueIgnoreCase - compare string to check against allowedList value while ignoring case sensitivity. Sets stringToCheck to allowedList value (including case) if equivalent.
            /// </summary>
            /// <param name="stringToCheck"></param>
            /// <returns></returns>   
            public bool? EqualsValueIgnoreCase(ref string stringToCheck, string allowedListValue, int lengthToTruncateTo)
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
                        tmpResult = null; //Always return null. Protects against a gigabyte of whitespace!!!
                    }
                    else
                    {
                        StringComparison ic = StringComparison.OrdinalIgnoreCase;

                        //Truncate first to lean towards more conservative. Have to pass in string in FormKC format.
                        string truncatedValue = SaniCore.Truncate.ToValidLength(stringToCheck, lengthToTruncateTo);
                        string limitedToASCII = SaniCore.NormalizeOrLimit.ToASCIIOnly(truncatedValue);

                        bool isSuccess = limitedToASCII.Equals(allowedListValue, ic);

                        if (isSuccess)
                        {
                            stringToCheck = allowedListValue;
                            tmpResult = true;
                        }
                        else
                        {
                            throw new Exception("StringToCheck does NOT equal allowedList value.");
                        }
                    }
                }
                catch (Exception ex)
                {
                    SaniExceptionHandler.TrackOrThrowException(TruncateLength, SaniType, SaniCore, "AllowedList: ", "Issue with AllowedList ASCII EqualsValueIgnoreCase method", stringToCheck, ex);
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
            /// StartsWithPrefix - compare string to check against allowedList value at the start of the string.
            /// </summary>
            /// <param name="stringToCheck"></param>
            /// <returns></returns>   
            public bool? StartsWithPrefix(ref string stringToCheck, string allowedListPrefix, int lengthToTruncateTo)
            {
                bool? tmpResult = false;

                try
                {
                    if (String.IsNullOrWhiteSpace(allowedListPrefix))
                    {
                        throw new Exception("AllowedList prefix cannot be null or empty!");
                    }

                    if (String.IsNullOrWhiteSpace(stringToCheck))
                    {
                        tmpResult = null; //Always return null. Protects against a gigabyte of whitespace!!!
                    }
                    else
                    {
                        StringComparison ord = StringComparison.Ordinal;

                        //Truncate first to lean towards more conservative. Have to pass in string in FormKC format.
                        string truncatedValue = SaniCore.Truncate.ToValidLength(stringToCheck, lengthToTruncateTo);
                        string normalizedUnicode = SaniCore.NormalizeOrLimit.NormalizeUnicode(truncatedValue);

                        bool isSuccess = (normalizedUnicode.StartsWith(allowedListPrefix, ord));

                        if (isSuccess)
                        {
                            stringToCheck = normalizedUnicode;
                            tmpResult = true;
                        }
                        else
                        {
                            throw new Exception("StringToCheck does NOT start with the allowedList prefix normalized.");
                        }
                    }
                }
                catch (Exception ex)
                {
                    SaniExceptionHandler.TrackOrThrowException(TruncateLength, SaniType, SaniCore, "AllowedList: ", "Issue with AllowedList Normalize StartsWithPrefix method", stringToCheck, ex);
                }
                return tmpResult;
            }

            /// <summary>
            /// EndsWithSuffix - compare string to check against allowedList value at the end of the string.
            /// </summary>
            /// <param name="stringToCheck"></param>
            /// <returns></returns>   
            public bool? EndsWithSuffix(ref string stringToCheck, string allowedListSuffix, int lengthToTruncateTo)
            {
                bool? tmpResult = false;

                try
                {
                    if (String.IsNullOrWhiteSpace(allowedListSuffix))
                    {
                        throw new Exception("AllowedList Suffix cannot be null or empty!");
                    }

                    if (String.IsNullOrWhiteSpace(stringToCheck))
                    {
                        tmpResult = null; //Always return null. Protects against a gigabyte of whitespace!!!
                    }
                    else
                    {
                        StringComparison ord = StringComparison.Ordinal;

                        //Truncate first to lean towards more conservative. Have to pass in string in FormKC format.
                        string truncatedValue = SaniCore.Truncate.ToValidLength(stringToCheck, lengthToTruncateTo);
                        string normalizedUnicode = SaniCore.NormalizeOrLimit.NormalizeUnicode(truncatedValue);

                        bool isSuccess = (normalizedUnicode.EndsWith(allowedListSuffix, ord));

                        if (isSuccess)
                        {
                            stringToCheck = normalizedUnicode;
                            tmpResult = true;
                        }
                        else
                        {
                            throw new Exception("StringToCheck does NOT end with the allowedList Suffix normalized.");
                        }
                    }
                }
                catch (Exception ex)
                {
                    SaniExceptionHandler.TrackOrThrowException(TruncateLength, SaniType, SaniCore, "AllowedList: ", "Issue with AllowedList Normalize EndsWithSuffix method", stringToCheck, ex);
                }
                return tmpResult;
            }

            /// <summary>
            /// StartsWithPrefixIgnoreCase - compare string to check against allowedList value at the start of the string ignoring case.
            /// </summary>
            /// <param name="stringToCheck"></param>
            /// <returns></returns>   
            public bool? StartsWithPrefixIgnoreCase(ref string stringToCheck, string allowedListPrefix, int lengthToTruncateTo)
            {
                bool? tmpResult = false;

                try
                {
                    if (String.IsNullOrWhiteSpace(allowedListPrefix))
                    {
                        throw new Exception("AllowedList prefix cannot be null or empty!");
                    }

                    if (String.IsNullOrWhiteSpace(stringToCheck))
                    {
                        tmpResult = null; //Always return null. Protects against a gigabyte of whitespace!!!
                    }
                    else
                    {
                        StringComparison ic = StringComparison.OrdinalIgnoreCase;

                        //Truncate first to lean towards more conservative. Have to pass in string in FormKC format.
                        string truncatedValue = SaniCore.Truncate.ToValidLength(stringToCheck, lengthToTruncateTo);
                        string normalizedUnicode = SaniCore.NormalizeOrLimit.NormalizeUnicode(truncatedValue);

                        bool isSuccess = (normalizedUnicode.StartsWith(allowedListPrefix, ic));

                        if (isSuccess)
                        {
                            stringToCheck = normalizedUnicode;
                            tmpResult = true;
                        }
                        else
                        {
                            throw new Exception("StringToCheck does NOT start with the allowedList Prefix normalized while ignoring case.");
                        }
                    }
                }
                catch (Exception ex)
                {
                    SaniExceptionHandler.TrackOrThrowException(TruncateLength, SaniType, SaniCore, "AllowedList: ", "Issue with AllowedList Normalize StartsWithPrefixIgnoreCase method", stringToCheck, ex);
                }
                return tmpResult;
            }

            /// <summary>
            /// EndsWithSuffixIgnoreCase - compare string to check against allowedList value at the end of the string ignoring case.
            /// </summary>
            /// <param name="stringToCheck"></param>
            /// <returns></returns>   
            public bool? EndsWithSuffixIgnoreCase(ref string stringToCheck, string allowedListSuffix, int lengthToTruncateTo)
            {
                bool? tmpResult = false;

                try
                {
                    if (String.IsNullOrWhiteSpace(allowedListSuffix))
                    {
                        throw new Exception("AllowedList Suffix cannot be null or empty!");
                    }

                    if (String.IsNullOrWhiteSpace(stringToCheck))
                    {
                        tmpResult = null; //Always return null. Protects against a gigabyte of whitespace!!!
                    }
                    else
                    {
                        StringComparison ic = StringComparison.OrdinalIgnoreCase;

                        //Truncate first to lean towards more conservative. Have to pass in string in FormKC format.
                        string truncatedValue = SaniCore.Truncate.ToValidLength(stringToCheck, lengthToTruncateTo);
                        string normalizedUnicode = SaniCore.NormalizeOrLimit.NormalizeUnicode(truncatedValue);

                        bool isSuccess = (normalizedUnicode.EndsWith(allowedListSuffix, ic));

                        if (isSuccess)
                        {
                            stringToCheck = normalizedUnicode;
                            tmpResult = true;
                        }
                        else
                        {
                            throw new Exception("StringToCheck does NOT start with the allowedList Suffix Normalize while ignoring case.");
                        }
                    }
                }
                catch (Exception ex)
                {
                    SaniExceptionHandler.TrackOrThrowException(TruncateLength, SaniType, SaniCore, "AllowedList: ", "Issue with AllowedList Normalize EndsWithSuffixIgnoreCase method", stringToCheck, ex);
                }
                return tmpResult;
            }

            /// <summary>
            /// EqualsValue - compare string to check against allowedList value. Sets stringToCheck to allowedList value if equivalent.
            /// </summary>
            /// <param name="stringToCheck"></param>
            /// <returns></returns>   
            public bool? EqualsValue(ref string stringToCheck, string allowedListValue, int lengthToTruncateTo)
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
                        tmpResult = null; //Always return null. Protects against a gigabyte of whitespace!!!
                    }
                    else
                    {
                        //Truncate first to lean towards more conservative. Have to pass in string in FormKC format.
                        string truncatedValue = SaniCore.Truncate.ToValidLength(stringToCheck, lengthToTruncateTo);
                        string normalizedUnicode = SaniCore.NormalizeOrLimit.NormalizeUnicode(truncatedValue);
                       
                        bool isSuccess = (normalizedUnicode.Equals(allowedListValue));

                        if (isSuccess)
                        {
                            stringToCheck = allowedListValue;
                            tmpResult = true;
                        }
                        else
                        {
                            throw new Exception("StringToCheck does NOT equal allowedList value.");
                        }
                    }
                }
                catch (Exception ex)
                {
                    SaniExceptionHandler.TrackOrThrowException(TruncateLength, SaniType, SaniCore, "AllowedList: ", "Issue with AllowedList Unicode EqualsValue method", stringToCheck, ex);
                }
                return tmpResult;
            }

            /// <summary>
            /// EqualsValueIgnoreCase - compare string to check against allowedList value while ignoring case sensitivity. Sets stringToCheck to allowedList value (including case) if equivalent.
            /// </summary>
            /// <param name="stringToCheck"></param>
            /// <returns></returns>   
            public bool? EqualsValueIgnoreCase(ref string stringToCheck, string allowedListValue, int lengthToTruncateTo)
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
                        tmpResult = null; //Always return null. Protects against a gigabyte of whitespace!!!
                    }
                    else
                    {
                        StringComparison ic = StringComparison.OrdinalIgnoreCase;

                        //Truncate first to lean towards more conservative. Have to pass in string in FormKC format.
                        string truncatedValue = SaniCore.Truncate.ToValidLength(stringToCheck, lengthToTruncateTo);
                        string normalizedUnicode = SaniCore.NormalizeOrLimit.NormalizeUnicode(truncatedValue);
                        
                        bool isSuccess = (normalizedUnicode.Equals(allowedListValue, ic));

                        if (isSuccess)
                        {
                            stringToCheck = allowedListValue;
                            tmpResult = true;
                        }
                        else
                        {
                            throw new Exception("StringToCheck does NOT equal allowedList value.");
                        }
                    }
                }
                catch (Exception ex)
                {
                    SaniExceptionHandler.TrackOrThrowException(TruncateLength, SaniType, SaniCore, "AllowedList: ", "Issue with AllowedList Unicode EqualsIgnoreCase method", stringToCheck, ex);
                }
                return tmpResult;
            }
        }

        //StartsWith, EndsWith and maybe an ApplyRegex
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
