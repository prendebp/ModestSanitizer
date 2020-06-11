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
    ///  Whitelist = 4
    ///  Check whitelist of valid values using ASCII or Unicode
    //   Why? To safely compare input string(s) to expected, valid values
    /// </summary>
    public class Whitelist
    {
        private Truncate Truncate { get; set; }
        private NormalizeOrLimit NormalizeOrLimit { get; set; }
        public Approach SanitizerApproach { get; set; }
        public Dictionary<Guid, KeyValuePair<SaniTypes, string>> SaniExceptions { get; set; }

        public Whitelist()
        {
        }

        public Whitelist(Approach sanitizerApproach)
        {
            SanitizerApproach = sanitizerApproach;
        }

        public Whitelist(Truncate truncate, NormalizeOrLimit normalizeOrLimit, Approach sanitizerApproach, Dictionary<Guid, KeyValuePair<SaniTypes, string>> saniExceptions) : this(sanitizerApproach)
        {
            Truncate = truncate;
            NormalizeOrLimit = normalizeOrLimit;
            SaniExceptions = saniExceptions;
        }

        /// <summary>
        /// Equals - compare string to check against whitelist value. Sets stringToCheck to whitelist value if equivalent.
        /// </summary>
        /// <param name="stringToCheck"></param>
        /// <returns></returns>   
        public bool? EqualsUsingASCII(ref string stringToCheck, string whitelistValue, int lengthToTruncateTo)
        {
            bool? tmpResult = false;

            try
            {
                if (String.IsNullOrWhiteSpace(whitelistValue))
                {
                    throw new Exception("Whitelist value cannot be null or empty!");
                }

                if (String.IsNullOrWhiteSpace(stringToCheck))
                {
                    tmpResult = null;
                }
                else
                {
                    string limitedToASCII = NormalizeOrLimit.ToASCIIOnly(stringToCheck);
                    string truncatedValue = Truncate.ToValidLength(limitedToASCII, lengthToTruncateTo);
                    bool isSuccess = (truncatedValue.Equals(whitelistValue));

                    if (isSuccess)
                    {
                        stringToCheck = whitelistValue;
                        tmpResult = true;
                    }
                    else
                    {
                        throw new Exception("StringToCheck does NOT match whitelist value.");
                    }
                }
            }
            catch (Exception ex)
            {
                TrackOrThrowException("Issue with Whitelist Equals method", stringToCheck, ex);
            }
            return tmpResult;
        }


        /// <summary>
        /// Equals - compare string to check against whitelist value while ignoring case sensitivity. Sets stringToCheck to whitelist value (including case) if equivalent.
        /// </summary>
        /// <param name="stringToCheck"></param>
        /// <returns></returns>   
        public bool? EqualsIgnoreCaseUsingASCII(ref string stringToCheck, string whitelistValue, int lengthToTruncateTo)
        {
            bool? tmpResult = false;

            try
            {
                if (String.IsNullOrWhiteSpace(whitelistValue))
                {
                    throw new Exception("Whitelist value cannot be null or empty!");
                }

                if (String.IsNullOrWhiteSpace(stringToCheck))
                {
                    tmpResult = null;
                }
                else
                {                    
                    string truncatedValue = Truncate.ToValidLength(stringToCheck, lengthToTruncateTo);
                    string limitedToASCII = NormalizeOrLimit.ToASCIIOnly(truncatedValue);
                    StringComparison ic = StringComparison.OrdinalIgnoreCase;

                    int initialLength = limitedToASCII.Length;
                    string stringPostReplacement = Replace(limitedToASCII, whitelistValue, string.Empty, ic);
                    int finalLength = stringPostReplacement.Length;

                    bool isSuccess = (finalLength == 0);

                    if (isSuccess)
                    {
                        stringToCheck = whitelistValue;
                        tmpResult = true;
                    }
                    else
                    {
                        throw new Exception("StringToCheck does NOT match whitelist value.");
                    }
                }
            }
            catch (Exception ex)
            {
                TrackOrThrowException("Issue with Whitelist EqualsIgnoreCase method", stringToCheck, ex);
            }
            return tmpResult;
        }

        //TODO: partial whitelist such as the domain of an email address? ^[a-zA-Z0-9_+&*-]+(?:\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,7}$

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
            string exceptionValue = Truncate.ToValidLength(valToClean, 5);

            if (SanitizerApproach == Approach.TrackExceptionsInList)
            {
                SaniExceptions.Add(Guid.NewGuid(), new KeyValuePair<SaniTypes, string>(SaniTypes.Whitelist, exceptionValue));
            }
            else
            {
                throw new SanitizerException(msg + (exceptionValue ?? String.Empty), ex);
            }
        }
    }//end of class
}//end of namespace
