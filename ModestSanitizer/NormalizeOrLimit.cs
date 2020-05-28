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
    ///  NormalizeOrLimit = 3
    ///  NormalizeUnicode or LimitToASCIIOnly
    //   Why? To assist with safe whitelisting
    /// </summary>
    public class NormalizeOrLimit
    {
        public Truncate Truncate { get; set; }
        public SaniApproach SanitizerApproach { get; set; }
        public Dictionary<Guid, KeyValuePair<SaniTypes, string>> SaniExceptions { get; set; }

        public NormalizeOrLimit()
        {
        }

        public NormalizeOrLimit(SaniApproach sanitizerApproach)
        {
            SanitizerApproach = sanitizerApproach;
        }

        public NormalizeOrLimit(Truncate truncate, SaniApproach sanitizerApproach, Dictionary<Guid, KeyValuePair<SaniTypes, string>> saniExceptions) : this(sanitizerApproach)
        {
            Truncate = truncate;
            SaniExceptions = saniExceptions;
        }

        /// <summary>
        /// Normalize Unicode for if you are planning to compare against a Unicode Whitelist (so you know which Normalization Form to use.)
        /// </summary>
        /// <param name="strToClean"></param>
        /// <returns></returns>   
        public string NormalizeUnicode(string strToClean)
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
                TrackOrThrowException("Error normalizing unicode: ", strToClean, ex);
            }

            return tmpResult;
        }


        /// <summary>
        /// Limit a Unicode string to just the limited subset of ASCII-compatible characters.
        /// </summary>
        /// <param name="strToClean"></param>
        /// <returns></returns>
        public string LimitToASCIIOnly(string strToClean)
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
                TrackOrThrowException("Error limiting unicode to ASCII: ", strToClean, ex);
            }
            return tmpResult;
        }

        private void TrackOrThrowException(string msg, string valToClean, Exception ex)
        {
            string exceptionValue = Truncate.TruncateToValidLength(valToClean, 5);

            if (SanitizerApproach == SaniApproach.TrackExceptionsInList)
            {
                SaniExceptions.Add(Guid.NewGuid(), new KeyValuePair<SaniTypes, string>(SaniTypes.NormalizeOrLimit, exceptionValue));
            }
            else
            {
                throw new SanitizerException(msg + (exceptionValue ?? String.Empty), ex);
            }
        }
    }//end of class
}//end of namespace
